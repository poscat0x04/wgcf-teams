use argh::FromArgs;

#[derive(FromArgs)]
/// Generate wireguard config for WARP for teams
pub struct Args {
    #[argh(option)]
    /// the name of your zero trust organization
    pub org: String,
    #[argh(switch, short = 'p')]
    /// whether to prompt for wireguard private key instead of
    /// randomly generating one
    pub prompt: bool,
}
