# A firewall that lets the whole internet reach the search and metrics ports.
resource "google_compute_firewall" "search" {
  name          = "search"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["9200", "9300"]
  }
}
