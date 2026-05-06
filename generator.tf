resource "aws_instance" "generator" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = "t2.micro"
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.generator.id]
  associate_public_ip_address = true
  key_name                    = var.key_name != "" ? var.key_name : null

  user_data = base64encode(templatefile("${path.module}/user_data_generator.sh", {
    elk_private_ip = aws_instance.elk.private_ip
  }))

  tags = { Name = "siem-generator" }
}