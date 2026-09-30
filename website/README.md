# THE VOID — Engagement Website

Red-team marketing site for demos. **Black-hole aesthetic** (singularity, event horizon, accretion glow) on the outside; points operators to the **clean CLI / Command Center** for real work.

- No pricing, no checkout, no “contact sales for a quote”
- Info + attitude for red team audiences
- Localhost serve only (demo-safe)
- Not Matrix-green cyberpunk — void / gravity / horizon

## Run

```bash
cd website
./serve.sh
# → http://127.0.0.1:8088
```

Or:

```bash
python3 -m http.server 8088 --bind 127.0.0.1
```

## Files

| Path | Role |
|------|------|
| `index.html` | Landing page |
| `css/styles.css` | Theme (acid/cyan/rose on near-black) |
| `js/app.js` | Matrix rain, typing, terminal sim, tabs |
| `assets/favicon.svg` | Mark |
| `serve.sh` | Localhost static server |

## Design split

| Surface | Vibe |
|---------|------|
| **This site** | Black hole field, photon/horizon palette, terminal theater |
| **CLI / Command Center** | Dense professional operator chrome |

## Related

- Operator guide: `../docs/OPERATOR_GUIDE.md`
- MCP scanner: `../mcp-tools/mcp-scanner/README.md`
- Command Center: `../commandcenter/`
