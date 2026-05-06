output "kibana_url" {
  value       = "http://${aws_instance.elk.public_ip}:5601"
  description = "Open this in your browser (~8 min after apply)"
}

output "elk_public_ip" {
  value = aws_instance.elk.public_ip
}

output "generator_public_ip" {
  value = aws_instance.generator.public_ip
}