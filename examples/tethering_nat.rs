#[macro_use]
extern crate error_chain;

use std::env;
use std::net::Ipv4Addr;
use pfctl::{PfCtl, NatRuleBuilder, AnchorKind, AddrFamily, Ip, Interface, Endpoint, Port, Proto, RulesetKind};
use ipnetwork::{IpNetwork, Ipv4Network};

error_chain! {
    foreign_links {
        Io(std::io::Error);
        ParseIntError(std::num::ParseIntError);
    }
}
quick_main!(run);

const ANCHOR_NAME: &str = "tethering_nat";

fn run() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        bail!("Usage: program <start|stop>");
    }

    let command = &args[1];
    let mut pf = PfCtl::new().chain_err(|| "Unable to connect to PF")?;

    match command.as_str() {
        "start" => {
            // Ensure anchors are added
            pf.try_add_anchor(ANCHOR_NAME, AnchorKind::Nat)
                .chain_err(|| "Unable to add test nat anchor")?;

            // Define the NAT rule
            let tethering_net = Ipv4Network::new(Ipv4Addr::new(172, 20, 10, 0), 24).unwrap();
            let nat_rule = NatRuleBuilder::default()
                .action(pfctl::NatRuleAction::NAT)
                .af(AddrFamily::Ipv4)
                .interface(Interface::from("bridge100"))
                .proto(Proto::Tcp)
                .from(Ip::from(IpNetwork::from(tethering_net)))
                .to(Endpoint::new(Ip::Any, Port::Any))
                .nat_to(Endpoint::new(Ip::from(Ipv4Addr::new(198, 18, 0, 1)), Port::Any))
                .pass(true)
                .build()
                .unwrap();

            // Add the NAT rule to the anchor
            pf.add_nat_rule(ANCHOR_NAME, &nat_rule)
                .chain_err(|| "Unable to add nat rule")?;
        },
        "stop" => {
            // Clean the rules under the specified anchor
            pf.flush_rules(ANCHOR_NAME, RulesetKind::Nat)
                .chain_err(|| "Unable to flush filter rules")?;
            println!("Flushed nat rules under anchor {}", ANCHOR_NAME);
        },
        _ => bail!("Invalid command. Use 'start' or 'stop'."),
    }
    Ok(())
}