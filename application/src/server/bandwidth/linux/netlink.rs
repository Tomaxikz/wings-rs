use anyhow::{Context, ensure};
use rustix::net::{
    self, AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType, netlink::SocketAddrNetlink,
};
use std::{
    ffi::CStr,
    os::fd::OwnedFd,
    time::{Duration, Instant},
};

const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_GETLINK: u16 = 18;
const RTM_NEWQDISC: u16 = 36;
const RTM_DELQDISC: u16 = 37;
const RTM_NEWTFILTER: u16 = 44;
const RTM_DELTFILTER: u16 = 45;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_MULTI: u16 = 0x2;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_DUMP_INTR: u16 = 0x10;
const NLM_F_REPLACE: u16 = 0x100;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_DUMP: u16 = 0x300;
const NLM_F_CREATE: u16 = 0x400;

const IFF_UP: u32 = 0x1;
const IFF_LOOPBACK: u32 = 0x8;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_LINKINFO: u16 = 18;
const IFLA_INFO_KIND: u16 = 1;

const TCA_KIND: u16 = 1;
const TCA_OPTIONS: u16 = 2;
const TCA_TBF_PARMS: u16 = 1;
const TCA_TBF_RATE64: u16 = 4;
const TCA_TBF_BURST: u16 = 6;
const TCA_FQ_CODEL_TARGET: u16 = 1;
const TCA_FQ_CODEL_LIMIT: u16 = 2;
const TCA_FQ_CODEL_INTERVAL: u16 = 3;
const TCA_FQ_CODEL_ECN: u16 = 4;
const TCA_FQ_CODEL_FLOWS: u16 = 5;
const TCA_FQ_CODEL_QUANTUM: u16 = 6;
const TCA_FQ_CODEL_MEMORY_LIMIT: u16 = 9;
const TCA_MATCHALL_ACT: u16 = 2;
const TCA_ACT_KIND: u16 = 1;
const TCA_ACT_OPTIONS: u16 = 2;
const TCA_MIRRED_PARMS: u16 = 2;
const TCA_EGRESS_REDIR: i32 = 1;
const TC_ACT_STOLEN: i32 = 4;
const ETH_P_ALL: u16 = 0x0003;

const ENOENT: i32 = 2;
const EINVAL: i32 = 22;
const EEXIST: i32 = 17;
const ENODEV: i32 = 19;

const TC_H_ROOT: u32 = u32::MAX;
const TC_H_INGRESS: u32 = 0xffff_fff1;
const INGRESS_HANDLE: u32 = 0xffff_0000;
const TC_LINKLAYER_ETHERNET: u8 = 1;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub index: u32,
    pub name: String,
    pub mtu: u32,
    pub flags: u32,
    pub kind: Option<String>,
}

impl Link {
    pub fn is_up(&self) -> bool {
        self.flags & IFF_UP != 0
    }

    pub fn is_loopback(&self) -> bool {
        self.flags & IFF_LOOPBACK != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shaping {
    pub rate: u64,
    pub burst: u32,
    pub memory: u32,
    pub packets: u32,
    pub quantum: u32,
    pub flows: u32,
    pub target: u32,
    pub interval: u32,
}

pub struct Route {
    socket: OwnedFd,
    sequence: u32,
}

impl Route {
    pub fn open() -> Result<Self, anyhow::Error> {
        let socket = net::socket_with(
            AddressFamily::NETLINK,
            SocketType::RAW,
            SocketFlags::CLOEXEC,
            None,
        )
        .context("failed to open netlink socket")?;
        net::connect(&socket, &SocketAddrNetlink::new(0, 0))?;

        Ok(Self {
            socket,
            sequence: 0,
        })
    }

    pub fn links(&mut self) -> Result<Vec<Link>, anyhow::Error> {
        self.request(RTM_GETLINK, NLM_F_DUMP, &link_message(0, 0))?
            .iter()
            .map(|reply| parse_link(reply))
            .collect()
    }

    pub fn shape(
        &mut self,
        index: u32,
        handle: u16,
        shaping: Shaping,
    ) -> Result<(), anyhow::Error> {
        let root = u32::from(handle) << 16;
        let child = u32::from(handle + 1) << 16;

        self.set_qdisc(
            index,
            root,
            TC_H_ROOT,
            "tbf",
            &tbf_options(shaping)?,
            NLM_F_REPLACE,
        )?;

        match self.set_qdisc(
            index,
            child,
            root | 1,
            "fq_codel",
            &fq_codel_options(shaping, true)?,
            NLM_F_REPLACE | NLM_F_EXCL,
        ) {
            Err(err) if errno(&err) == Some(EEXIST) => self.set_qdisc(
                index,
                child,
                root | 1,
                "fq_codel",
                &fq_codel_options(shaping, false)?,
                NLM_F_REPLACE,
            ),
            result => result,
        }
    }

    pub fn unshape(&mut self, index: u32, handle: u16) -> Result<(), anyhow::Error> {
        let message = qdisc_message(index, u32::from(handle) << 16, TC_H_ROOT);

        match self.request(RTM_DELQDISC, NLM_F_ACK, &message) {
            Err(err) if matches!(errno(&err), Some(ENOENT | EINVAL)) => Ok(()),
            result => result.map(drop),
        }
    }

    pub fn add_ifb(&mut self, name: &str) -> Result<(), anyhow::Error> {
        let mut info = Vec::new();
        attribute(&mut info, IFLA_INFO_KIND, &nul_terminated("ifb"))?;
        let mut message = link_message(0, IFF_UP);
        attribute(&mut message, IFLA_IFNAME, &nul_terminated(name))?;
        attribute(&mut message, IFLA_LINKINFO, &info)?;

        match self.request(RTM_NEWLINK, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, &message) {
            Err(err) if errno(&err) == Some(EEXIST) => Ok(()),
            result => result.map(drop),
        }
        .context("failed to create ifb device")
    }

    pub fn set_up(&mut self, index: u32) -> Result<(), anyhow::Error> {
        self.request(RTM_NEWLINK, NLM_F_ACK, &link_message(index, IFF_UP))
            .map(drop)
    }

    pub fn delete_link(&mut self, index: u32) -> Result<(), anyhow::Error> {
        match self.request(RTM_DELLINK, NLM_F_ACK, &link_message(index, 0)) {
            Err(err) if errno(&err) == Some(ENODEV) => Ok(()),
            result => result.map(drop),
        }
    }

    pub fn add_ingress(&mut self, index: u32) -> Result<(), anyhow::Error> {
        let mut message = qdisc_message(index, INGRESS_HANDLE, TC_H_INGRESS);
        attribute(&mut message, TCA_KIND, &nul_terminated("ingress"))?;

        match self.request(
            RTM_NEWQDISC,
            NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            &message,
        ) {
            Err(err) if errno(&err) == Some(EEXIST) => Ok(()),
            result => result.map(drop),
        }
        .context("failed to install ingress qdisc")
    }

    pub fn delete_ingress(&mut self, index: u32) -> Result<(), anyhow::Error> {
        let message = qdisc_message(index, INGRESS_HANDLE, TC_H_INGRESS);

        match self.request(RTM_DELQDISC, NLM_F_ACK, &message) {
            Err(err) if matches!(errno(&err), Some(ENOENT | EINVAL)) => Ok(()),
            result => result.map(drop),
        }
    }

    pub fn redirect(&mut self, index: u32, target: u32) -> Result<(), anyhow::Error> {
        let info = (1 << 16) | u32::from(ETH_P_ALL.to_be());
        let mut message = tc_message(index, 1, INGRESS_HANDLE, info);
        attribute(&mut message, TCA_KIND, &nul_terminated("matchall"))?;
        attribute(&mut message, TCA_OPTIONS, &matchall_redirect(target)?)?;

        let flags = NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
        match self.request(RTM_NEWTFILTER, flags, &message) {
            Err(err) if errno(&err) == Some(EEXIST) => {
                self.request(
                    RTM_DELTFILTER,
                    NLM_F_ACK,
                    &tc_message(index, 1, INGRESS_HANDLE, info),
                )?;
                self.request(RTM_NEWTFILTER, flags, &message)
            }
            result => result,
        }
        .context("failed to install ingress redirect")
        .map(drop)
    }

    fn set_qdisc(
        &mut self,
        index: u32,
        handle: u32,
        parent: u32,
        kind: &str,
        options: &[u8],
        flags: u16,
    ) -> Result<(), anyhow::Error> {
        let mut message = qdisc_message(index, handle, parent);
        attribute(&mut message, TCA_KIND, &nul_terminated(kind))?;
        attribute(&mut message, TCA_OPTIONS, options)?;

        self.request(RTM_NEWQDISC, NLM_F_ACK | NLM_F_CREATE | flags, &message)
            .with_context(|| format!("failed to install {kind} qdisc"))
            .map(drop)
    }

    fn request(
        &mut self,
        kind: u16,
        flags: u16,
        payload: &[u8],
    ) -> Result<Vec<Vec<u8>>, anyhow::Error> {
        self.sequence = self.sequence.wrapping_add(1);
        let mut request = Vec::with_capacity(16 + payload.len());
        request.extend(u32::try_from(16 + payload.len())?.to_ne_bytes());
        request.extend(kind.to_ne_bytes());
        request.extend((flags | NLM_F_REQUEST).to_ne_bytes());
        request.extend(self.sequence.to_ne_bytes());
        request.extend(0u32.to_ne_bytes());
        request.extend(payload);

        ensure!(
            net::send(&self.socket, &request, SendFlags::empty())? == request.len(),
            "incomplete netlink request"
        );

        let deadline = Instant::now() + REQUEST_TIMEOUT;

        let dump = flags & NLM_F_DUMP == NLM_F_DUMP;
        let mut buffer = vec![0u8; 65536];
        let mut replies = Vec::new();

        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .context("netlink request timed out")?;
            net::sockopt::set_socket_timeout(
                &self.socket,
                net::sockopt::Timeout::Recv,
                Some(remaining),
            )?;

            let (_, length, source) =
                match net::recvfrom(&self.socket, &mut buffer, RecvFlags::TRUNC) {
                    Err(rustix::io::Errno::INTR) => continue,
                    result => result.context("failed to receive netlink reply")?,
                };
            let source = SocketAddrNetlink::try_from(source.context("missing netlink sender")?)?;
            ensure!(
                source.pid() == 0,
                "netlink reply did not come from the kernel"
            );

            let mut messages = buffer.get(..length).context("truncated netlink datagram")?;
            while !messages.is_empty() {
                let length = u32::from_ne_bytes(read(messages, 0)?) as usize;
                ensure!(length >= 16, "invalid netlink message length");
                let message = messages
                    .get(..length)
                    .context("truncated netlink message")?;
                let reply_kind = u16::from_ne_bytes(read(message, 4)?);
                let reply_flags = u16::from_ne_bytes(read(message, 6)?);
                let data = message.get(16..).context("missing netlink payload")?;
                messages = messages
                    .get(length.next_multiple_of(4).min(messages.len())..)
                    .unwrap_or_default();

                if u32::from_ne_bytes(read(message, 8)?) != self.sequence {
                    continue;
                }
                ensure!(
                    reply_flags & NLM_F_DUMP_INTR == 0,
                    "interrupted netlink dump"
                );

                match reply_kind {
                    NLMSG_ERROR => {
                        let code = i32::from_ne_bytes(read(data, 0)?);
                        if code != 0 {
                            return Err(std::io::Error::from_raw_os_error(-code))
                                .context("netlink request rejected by the kernel");
                        }

                        return Ok(replies);
                    }
                    NLMSG_DONE if dump => return Ok(replies),
                    _ => {
                        replies.push(data.to_vec());

                        if !dump && reply_flags & NLM_F_MULTI == 0 && flags & NLM_F_ACK == 0 {
                            return Ok(replies);
                        }
                    }
                }
            }
        }
    }
}

fn errno(err: &anyhow::Error) -> Option<i32> {
    err.chain()
        .find_map(|cause| cause.downcast_ref::<std::io::Error>()?.raw_os_error())
}

fn read<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], anyhow::Error> {
    Ok(bytes
        .get(offset..offset + N)
        .context("truncated netlink field")?
        .try_into()?)
}

fn attribute(bytes: &mut Vec<u8>, kind: u16, value: &[u8]) -> Result<(), anyhow::Error> {
    bytes.extend(u16::try_from(4 + value.len())?.to_ne_bytes());
    bytes.extend(kind.to_ne_bytes());
    bytes.extend(value);
    bytes.resize(bytes.len().next_multiple_of(4), 0);

    Ok(())
}

fn attributes(mut bytes: &[u8]) -> Result<Vec<(u16, &[u8])>, anyhow::Error> {
    let mut attributes = Vec::new();

    while bytes.len() >= 4 {
        let length = usize::from(u16::from_ne_bytes(read(bytes, 0)?));
        let kind = u16::from_ne_bytes(read(bytes, 2)?) & 0x3fff;
        ensure!(length >= 4, "invalid netlink attribute length");
        attributes.push((
            kind,
            bytes
                .get(4..length)
                .context("truncated netlink attribute")?,
        ));
        bytes = bytes
            .get(length.next_multiple_of(4).min(bytes.len())..)
            .unwrap_or_default();
    }

    Ok(attributes)
}

fn nul_terminated(value: &str) -> Vec<u8> {
    let mut bytes = value.as_bytes().to_vec();
    bytes.push(0);

    bytes
}

fn link_message(index: u32, flags: u32) -> Vec<u8> {
    let mut message = vec![0u8; 4];
    message.extend(index.to_ne_bytes());
    message.extend(flags.to_ne_bytes());
    message.extend(flags.to_ne_bytes());

    message
}

fn parse_link(reply: &[u8]) -> Result<Link, anyhow::Error> {
    let index = u32::from_ne_bytes(read(reply, 4)?);
    let flags = u32::from_ne_bytes(read(reply, 8)?);
    let mut name = None;
    let mut mtu = None;
    let mut kind = None;

    for (attribute, value) in attributes(reply.get(16..).context("truncated interface message")?)? {
        match attribute {
            IFLA_IFNAME => name = Some(CStr::from_bytes_until_nul(value)?.to_str()?.to_string()),
            IFLA_MTU => mtu = Some(u32::from_ne_bytes(read(value, 0)?)),
            IFLA_LINKINFO => {
                for (info, value) in attributes(value)? {
                    if info == IFLA_INFO_KIND {
                        kind = Some(CStr::from_bytes_until_nul(value)?.to_str()?.to_string());
                    }
                }
            }
            _ => {}
        }
    }

    Ok(Link {
        index,
        name: name.context("kernel omitted interface name")?,
        mtu: mtu.context("kernel omitted interface mtu")?,
        flags,
        kind,
    })
}

fn qdisc_message(index: u32, handle: u32, parent: u32) -> Vec<u8> {
    tc_message(index, handle, parent, 0)
}

fn tc_message(index: u32, handle: u32, parent: u32, info: u32) -> Vec<u8> {
    let mut message = vec![0u8; 4];
    message.extend(index.to_ne_bytes());
    message.extend(handle.to_ne_bytes());
    message.extend(parent.to_ne_bytes());
    message.extend(info.to_ne_bytes());

    message
}

fn tbf_options(shaping: Shaping) -> Result<Vec<u8>, anyhow::Error> {
    let mut params = Vec::with_capacity(36);
    params.extend([0, TC_LINKLAYER_ETHERNET]);
    params.extend(0u16.to_ne_bytes());
    params.extend((-1i16).to_ne_bytes());
    params.extend(0u16.to_ne_bytes());
    params.extend(u32::try_from(shaping.rate.min(u64::from(u32::MAX)))?.to_ne_bytes());
    params.extend([0u8; 12]);
    params.extend(shaping.memory.to_ne_bytes());
    params.extend([0u8; 8]);

    let mut options = Vec::new();
    attribute(&mut options, TCA_TBF_PARMS, &params)?;
    attribute(&mut options, TCA_TBF_RATE64, &shaping.rate.to_ne_bytes())?;
    attribute(&mut options, TCA_TBF_BURST, &shaping.burst.to_ne_bytes())?;

    Ok(options)
}

fn matchall_redirect(target: u32) -> Result<Vec<u8>, anyhow::Error> {
    let mut parms = Vec::with_capacity(28);
    parms.extend(0u32.to_ne_bytes());
    parms.extend(0u32.to_ne_bytes());
    parms.extend(TC_ACT_STOLEN.to_ne_bytes());
    parms.extend(0i32.to_ne_bytes());
    parms.extend(0i32.to_ne_bytes());
    parms.extend(TCA_EGRESS_REDIR.to_ne_bytes());
    parms.extend(target.to_ne_bytes());

    let mut mirred = Vec::new();
    attribute(&mut mirred, TCA_MIRRED_PARMS, &parms)?;
    let mut action = Vec::new();
    attribute(&mut action, TCA_ACT_KIND, &nul_terminated("mirred"))?;
    attribute(&mut action, TCA_ACT_OPTIONS, &mirred)?;
    let mut actions = Vec::new();
    attribute(&mut actions, 1, &action)?;
    let mut options = Vec::new();
    attribute(&mut options, TCA_MATCHALL_ACT, &actions)?;

    Ok(options)
}

fn fq_codel_options(shaping: Shaping, create: bool) -> Result<Vec<u8>, anyhow::Error> {
    let mut options = Vec::new();
    if create {
        attribute(
            &mut options,
            TCA_FQ_CODEL_FLOWS,
            &shaping.flows.to_ne_bytes(),
        )?;
    }

    for (kind, value) in [
        (TCA_FQ_CODEL_TARGET, shaping.target),
        (TCA_FQ_CODEL_LIMIT, shaping.packets),
        (TCA_FQ_CODEL_INTERVAL, shaping.interval),
        (TCA_FQ_CODEL_ECN, 1),
        (TCA_FQ_CODEL_QUANTUM, shaping.quantum),
        (TCA_FQ_CODEL_MEMORY_LIMIT, shaping.memory),
    ] {
        attribute(&mut options, kind, &value.to_ne_bytes())?;
    }

    Ok(options)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attributes_round_trip_with_padding() {
        let mut bytes = Vec::new();
        attribute(&mut bytes, IFLA_IFNAME, b"eth0\0").unwrap();
        attribute(&mut bytes, IFLA_MTU, &1500u32.to_ne_bytes()).unwrap();

        assert_eq!(bytes.len(), 20);
        assert_eq!(
            attributes(&bytes).unwrap(),
            [
                (IFLA_IFNAME, &b"eth0\0"[..]),
                (IFLA_MTU, &1500u32.to_ne_bytes()[..])
            ]
        );
    }

    #[test]
    fn parses_link_flags_and_kind() {
        let mut info = Vec::new();
        attribute(&mut info, IFLA_INFO_KIND, b"veth\0").unwrap();
        let mut reply = link_message(17, IFF_UP);
        attribute(&mut reply, IFLA_IFNAME, b"eth0\0").unwrap();
        attribute(&mut reply, IFLA_MTU, &1500u32.to_ne_bytes()).unwrap();
        attribute(&mut reply, IFLA_LINKINFO, &info).unwrap();

        let link = parse_link(&reply).unwrap();
        assert_eq!(
            link,
            Link {
                index: 17,
                name: "eth0".into(),
                mtu: 1500,
                flags: IFF_UP,
                kind: Some("veth".into()),
            }
        );
        assert!(link.is_up() && !link.is_loopback());
    }

    #[test]
    fn redirect_action_matches_kernel_layout() {
        let options = matchall_redirect(42).unwrap();
        let [(TCA_MATCHALL_ACT, actions)] = attributes(&options).unwrap()[..] else {
            panic!("missing matchall action");
        };
        let [(1, action)] = attributes(actions).unwrap()[..] else {
            panic!("missing action entry");
        };
        let action = attributes(action).unwrap();
        assert_eq!(action[0], (TCA_ACT_KIND, &b"mirred\0"[..]));
        let [(TCA_MIRRED_PARMS, parms)] = attributes(action[1].1).unwrap()[..] else {
            panic!("missing mirred parameters");
        };

        assert_eq!(parms.len(), 28);
        assert_eq!(i32::from_ne_bytes(read(parms, 8).unwrap()), TC_ACT_STOLEN);
        assert_eq!(
            i32::from_ne_bytes(read(parms, 20).unwrap()),
            TCA_EGRESS_REDIR
        );
        assert_eq!(u32::from_ne_bytes(read(parms, 24).unwrap()), 42);
    }

    #[test]
    fn tbf_parameters_match_kernel_layout() {
        let shaping = Shaping {
            rate: 1_000_000,
            burst: 5000,
            memory: 65536,
            packets: 64,
            quantum: 1514,
            flows: 4096,
            target: 5000,
            interval: 100_000,
        };
        let options = tbf_options(shaping).unwrap();
        let options = attributes(&options).unwrap();

        let (_, params) = options[0];
        assert_eq!(params.len(), 36);
        assert_eq!(params[1], TC_LINKLAYER_ETHERNET);
        assert_eq!(u32::from_ne_bytes(read(params, 8).unwrap()), 1_000_000);
        assert_eq!(u32::from_ne_bytes(read(params, 24).unwrap()), 65536);
        assert_eq!(
            options[1],
            (TCA_TBF_RATE64, &1_000_000u64.to_ne_bytes()[..])
        );
        assert_eq!(options[2], (TCA_TBF_BURST, &5000u32.to_ne_bytes()[..]));
    }
}
