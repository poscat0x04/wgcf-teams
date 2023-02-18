use clap::Parser;

#[derive(Parser)]
#[command(author, version)]
#[command(about = "Generate wireguard config for WARP for teams")]
pub struct Arg {
    // @formatter:off
    #[arg(
        long,
        help = "the name of your zero trust organization"
    )]
    // @formatter:on
    pub org: String,
    // @formatter:off
    #[arg(
        short = 'p',
        long,
        default_value_t = false,
        help = "prompt for wireguard private key instead of randomly generating one"
    )]
    // @formatter:on
    pub prompt: bool,
}
