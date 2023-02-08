# wgcf-teams

Extract wireguard configurations from cloudflare's warp for teams

## Installing

### Using Nix

wgcf-teams is packaged as a flake. To install wgcf-teams, simply add it to your
flake input and import the overlay.

Alternatively, you can directly build from development branch

```
nix build "github:poscat0x04/wgcf-teams"
```

### Downloading from release

For each release, a binary is provided for each OS which you can download and add to your
`PATH`.

## Contributing

See devnote.md for developer notes and todo.md for the todo list of this project
