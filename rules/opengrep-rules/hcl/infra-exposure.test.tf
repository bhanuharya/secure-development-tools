# Annotated tests for hcl/infra-exposure.yaml (generic regex rule).
# ruleid: scp.hcl.gcp.firewall-open-internal-port
resource "google_compute_firewall" "search" {
  name          = "search"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["9200", "9300"]
  }
}

# ruleid: scp.hcl.gcp.firewall-open-internal-port
resource "google_compute_firewall" "broker" {
  name          = "broker"
  allow {
    protocol = "tcp"
    ports    = ["9092"]
  }
  source_ranges = ["0.0.0.0/0"]
}

# ok: scp.hcl.gcp.firewall-open-internal-port
resource "google_compute_firewall" "office" {
  source_ranges = ["10.0.0.0/8"]
  allow {
    protocol = "tcp"
    ports    = ["9200"]
  }
}

# ok: scp.hcl.gcp.firewall-open-internal-port
resource "google_compute_firewall" "web" {
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

# ok: scp.hcl.gcp.firewall-open-internal-port
resource "google_compute_firewall" "office-local" {
  source_ranges = ["10.0.0.0/8"]
  allow {
    protocol = "tcp"
    ports    = ["5432"]
  }
}
