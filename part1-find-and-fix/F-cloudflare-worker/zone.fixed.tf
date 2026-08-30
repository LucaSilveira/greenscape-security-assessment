# infra/cloudflare/zone.tf (fixed)
resource "cloudflare_zone_settings_override" "greenscape" {
  zone_id = var.zone_id
  settings {
    ssl             = "full_strict"
    min_tls_version = "1.2"
    security_level  = "medium"
  }
}

resource "cloudflare_record" "api_origin" {
  zone_id = var.zone_id
  name    = "origin" # origin.greenscape.com
  type    = "A"
  value   = "52.14.207.33" # the EKS ingress ALB
  proxied = true            # was false — routes through Cloudflare instead of exposing the ALB directly
}

# Defense-in-depth: the ALB's security group should additionally restrict inbound
# traffic to Cloudflare's published IP ranges (https://www.cloudflare.com/ips/), so a
# direct hit on the ALB's IP/DNS still fails even if a proxied=false record ever
# reappears by mistake.
