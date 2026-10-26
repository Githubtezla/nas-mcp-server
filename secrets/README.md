Put the Cloudflare tunnel token into a file named `cf_tunnel_token` in this folder (one line, the long token shown when you create the tunnel).

Everything in this folder except this README is ignored by git. The `fixperms` service copies the token to `secrets/cf/`, readable only for the cloudflared container.
