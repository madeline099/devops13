provider "google" {
  region      = var.region
  zone        = var.zone
  project     = var.project
  credentials = file(var.credentials)
}

provider "google-beta" {
  region      = var.region
  project     = var.project
}

#network

resource "google_compute_network" "gradproj-network" {
  name                    = var.vpc-network
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "private-subnet-gradproj" {
  name          = var.prv-subnet
  ip_cidr_range = "10.10.20.0/24"
  region        = var.region
  network       = google_compute_network.gradproj-network.id
}

resource "google_compute_subnetwork" "public-subnet-gradproj" {
  name          = var.pub-subnet
  ip_cidr_range = "10.10.10.0/24"
  region        = var.region
  network       = google_compute_network.gradproj-network.id
}

#external load
#http

resource "google_compute_backend_service" "backend" {
  name          = "compute-backend"
  protocol      = "HTTP"
  health_checks = [google_compute_health_check.hc.id]
  depends_on    = [google_compute_instance_group_manager.all]
}

resource "google_compute_global_address" "default" {
  project      = var.project
  name         = "${var.forward-rule}-address"
  ip_version   = "IPV4"
  address_type = "EXTERNAL"
}

resource "google_compute_target_http_proxy" "http" {
  count   = var.enable_http ? 1 : 0
  project = var.project
  name    = "${var.forward-rule}-http-proxy"
  url_map = google_compute_url_map.urlmap.id
}

resource "google_compute_url_map" "urlmap" {
  name        = "urlmap"

  default_service = google_compute_backend_service.backend.id

 }

resource "google_compute_global_forwarding_rule" "http" {
  provider   = google-beta
  count      = var.enable_http ? 1 : 0
  project    = var.project
  name       = "${var.forward-rule}-http-rule"
  target     = google_compute_target_http_proxy.http[0].self_link
  ip_address = google_compute_global_address.default.address
  port_range = "80"

  depends_on = [google_compute_global_address.default]

}

resource "google_compute_health_check" "hc" {
  name               = "http-health-check"
  check_interval_sec = 1
  timeout_sec        = 1

  http_health_check {
    port = "80"
   }
}

#https

resource "google_compute_backend_service" "backend2" {
  name          = "compute-backend2"
  protocol      = "HTTPS"
  health_checks = [google_compute_health_check.hc.id]
  depends_on    = [google_compute_instance_group.all]
}

resource "google_compute_global_forwarding_rule" "https" {
  provider   = google-beta
  project    = var.project
  count      = var.enable_ssl ? 1 : 0
  name       = "${var.forward-rule}-https-rule"
  target     = google_compute_target_https_proxy.default[0].self_link
  ip_address = google_compute_global_address.default.address
  port_range = "443"
  depends_on = [google_compute_global_address.default]

}

resource "google_compute_target_https_proxy" "default" {
  project = var.project
  count   = var.enable_ssl ? 1 : 0
  name    = "${var.forward-rule}-https-proxy"
  url_map = google_compute_url_map.urlmap2.id

  ssl_certificates = [google_compute_ssl_certificate.certificate.id]
}

resource "google_compute_url_map" "urlmap2" {
  name        = "urlmap2"

  default_service = google_compute_backend_service.backend2.id

 }

#SSL

resource "tls_self_signed_cert" "cert" {
  count = var.enable_ssl ? 1 : 0

  key_algorithm   = "RSA"
  private_key_pem = join("", tls_private_key.private_key.*.private_key_pem)

  subject {
    common_name  = var.custom_domain_name
   }

  validity_period_hours = 12

  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]
}

resource "tls_private_key" "private_key" {
  count       = var.enable_ssl ? 1 : 0
  algorithm   = "RSA"
  ecdsa_curve = "P256"
}

resource "google_compute_ssl_certificate" "certificate" {
  project = var.project

  description = "SSL Certificate"
  private_key = join("", tls_private_key.private_key.*.private_key_pem)
  certificate = join("", tls_self_signed_cert.cert.*.cert_pem)

  lifecycle {
    create_before_destroy = true
  }
}

resource "google_compute_instance_group_manager" "all" {
  project   = var.project
  name      = "${var.app-name}-instance-group"
  zone      = var.zone
  base_instance_name  = "${var.app-name}-app"

  version {
    instance_template = google_compute_instance_template.app.id
  }
  lifecycle {
    create_before_destroy = true
  }
  named_port {
    name      = "custom-ssh"
    port      = 22
  }
  named_port {
    name = "http"
    port = 80
  }
}

#firewall

resource "google_compute_firewall" "gradproj-firewall1" {
  name        = "gradproj-firewall1"
  network     = google_compute_network.gradproj-network.name
  allow {
    protocol  = "tcp"
    ports     = ["443"]
  }
 target_tags = ["app"]
 direction   = "INGRESS"
}

resource "google_compute_firewall" "gradproj-firewall2" {
  name        = "gradproj-firewall2"
  network     = google_compute_network.gradproj-network.name
  allow {
    protocol  = "tcp"
    ports     = ["9200-9300"]
  }
 target_tags = ["elastic-cluster"]
 direction   = "INGRESS"
}

resource "google_compute_firewall" "allow-ingress-from-iap" {
  name        = "allow-ingress-from-iap"
  network     = google_compute_network.gradproj-network.name
  source_ranges = ["35.235.240.0/20"]
  allow {
    protocol  = "tcp"
     }
 }

resource "google_compute_firewall" "ssh-rule" {
  name = "custom-ssh"
  network = google_compute_network.gradproj-network.name
  allow {
    protocol = "tcp"
    ports = ["22"]
  }
  target_tags = ["app", "elastic-cluster"]
  source_ranges = ["0.0.0.0/0"]
}

#app instance

resource "google_compute_instance_template" "app" {
  name          = "app"
  machine_type  = "e2-medium"
  region        = var.region
  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }
  tags = ["app", "http"]
  disk {
    source_image  = "centos-cloud/centos-7"
    auto_delete   = true
    boot          = true
  }

  metadata = {
    startup-script = file(var.app-script-path)
  }

  network_interface {
    subnetwork  = google_compute_subnetwork.public-subnet-gradproj.name
    access_config {
      // EPHEMERAL IP
     }
  }
}

resource "google_compute_autoscaler" "autoscaler" {
 name   = "my-autoscaler"
 target = google_compute_instance_group_manager.all.id

 autoscaling_policy {
   max_replicas    = 2
   min_replicas    = 1
   cooldown_period = 600
   cpu_utilization {
      target = 0.85
    }

 }
}

# GKE

resource "google_container_cluster" "elastic-cluster" {
  provider          = google-beta
  project           = var.project
  name              = "elastic-cluster"
  location          = var.region
#  load_config_file  = false
  network           = google_compute_network.gradproj-network.name
  subnetwork        = google_compute_subnetwork.private-subnet-gradproj.name

  remove_default_node_pool = true
  initial_node_count       = 1

  cluster_autoscaling {
    enabled = true
    autoscaling_profile = "OPTIMIZE_UTILIZATION"
    resource_limits {
      resource_type = "cpu"
      minimum = 1
      maximum = 4
    }
    resource_limits {
      resource_type = "memory"
      minimum = 4
      maximum = 16
    }
  }
}

resource "google_container_node_pool" "primary_nodes" {
  name       = "elastic-node-pool"
  location   = var.region
  cluster    = google_container_cluster.elastic-cluster.name
  node_count = 1

  node_config {
    machine_type = "e2-medium"
    disk_size_gb = 10

    service_account = google_service_account.cluster-service.email
    oauth_scopes    = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]
  }
}

resource "google_service_account" "cluster-service" {
  account_id  = "cluster-service-account"
  project = var.project
}

