# We set AWS as the cloud platform to use
provider "aws" {
   region  = "us-east-2"
   access_key = var.access_key
   secret_key = var.secret_key
 }

# We create a new VPC
resource "aws_vpc" "vpc" {
   cidr_block = "192.168.0.0/16"
   instance_tenancy = "default"
   tags = {
      Name = "VPC"
   }
   enable_dns_hostnames = true
}

# We create a public subnet
# Instances will have a dynamic public IP and be accessible via the internet gateway
resource "aws_subnet" "public_subnet1" {
   depends_on = [
      aws_vpc.vpc,
   ]
   vpc_id = aws_vpc.vpc.id
   cidr_block = "192.168.0.0/24"
   availability_zone_id = "use2-az1"
   tags = {
      Name = "public-subnet1"
   }
   map_public_ip_on_launch = true
}

resource "aws_subnet" "public_subnet2" {
   depends_on = [
      aws_vpc.vpc,
   ]
   vpc_id = aws_vpc.vpc.id
   cidr_block = "192.168.1.0/24"
   availability_zone_id = "use2-az2"
   tags = {
      Name = "public-subnet2"
   }
   map_public_ip_on_launch = true
}

# We create a private subnet
# Instances will not be accessible via the internet gateway
resource "aws_subnet" "private_subnet1" {
   depends_on = [
      aws_vpc.vpc,
   ]
   vpc_id = aws_vpc.vpc.id
   cidr_block = "192.168.2.0/24"
   availability_zone_id = "use2-az1"
   tags = {
      Name = "private-subnet1"
   }
}

resource "aws_subnet" "private_subnet2" {
   depends_on = [
      aws_vpc.vpc,
   ]
   vpc_id = aws_vpc.vpc.id
   cidr_block = "192.168.3.0/24"
   availability_zone_id = "use2-az2"
   tags = {
      Name = "private-subnet2"
   }
}

# We create an internet gateway
# Allows communication between our VPC and the internet
resource "aws_internet_gateway" "internet_gateway" {
   depends_on = [
      aws_vpc.vpc,
   ]
   vpc_id = aws_vpc.vpc.id
   tags = {
      Name = "internet-gateway",
   }
}

# We create a route table with target as our internet gateway and destination as "internet"
# Set of rules used to determine where network traffic is directed
resource "aws_route_table" "IG_route_table1" {
   depends_on = [
      aws_vpc.vpc,
      aws_internet_gateway.internet_gateway,
   ]
   vpc_id = aws_vpc.vpc.id
   route {
      cidr_block = "0.0.0.0/0"
      gateway_id = aws_internet_gateway.internet_gateway.id
   }
   tags = {
      Name = "IG-route-table1"
   }
}

resource "aws_route_table" "IG_route_table2" {
   depends_on = [
      aws_vpc.vpc,
      aws_internet_gateway.internet_gateway,
   ]
   vpc_id = aws_vpc.vpc.id
   route {
      cidr_block = "0.0.0.0/0"
      gateway_id = aws_internet_gateway.internet_gateway.id
   }
   tags = {
      Name = "IG-route-table2"
   }
}

# We associate our route table to the public subnet
# Makes the subnet public because it has a route to the internet via our internet gateway
resource "aws_route_table_association" "associate_routetable_to_public_subnet1" {
   depends_on = [
      aws_subnet.public_subnet1,
      aws_route_table.IG_route_table1,
   ]
   subnet_id = aws_subnet.public_subnet1.id
   route_table_id = aws_route_table.IG_route_table1.id
}

resource "aws_route_table_association" "associate_routetable_to_public_subnet2" {
   depends_on = [
      aws_subnet.public_subnet2,
      aws_route_table.IG_route_table2,
   ]
   subnet_id = aws_subnet.public_subnet2.id
   route_table_id = aws_route_table.IG_route_table2.id
}

# We create an elastic IP 
# A static public IP address that we can assign to any EC2 instance
resource "aws_eip" "elastic_ip1" {
   vpc = true
}

resource "aws_eip" "elastic_ip2" {
   vpc = true
}

# We create a NAT gateway with a required public IP
# Lives in a public subnet and prevents externally initiated traffic to our private subnet
# Allows initiated outbound traffic to the Internet or other AWS services
resource "aws_nat_gateway" "nat_gateway1" {
   depends_on = [
      aws_subnet.public_subnet1,
      aws_eip.elastic_ip1,
   ]
   allocation_id = aws_eip.elastic_ip1.id
   subnet_id = aws_subnet.public_subnet1.id
   tags = {
      Name = "nat-gateway1"
   }
}

resource "aws_nat_gateway" "nat_gateway2" {
   depends_on = [
      aws_subnet.public_subnet2,
      aws_eip.elastic_ip2,
   ]
   allocation_id = aws_eip.elastic_ip2.id
   subnet_id = aws_subnet.public_subnet2.id
   tags = {
      Name = "nat-gateway2"
   }
}

# We create a route table with target as NAT gateway and destination as "internet"
# Set of rules used to determine where network traffic is directed
resource "aws_route_table" "NAT_route_table1" {
   depends_on = [
      aws_vpc.vpc,
      aws_nat_gateway.nat_gateway1,
   ]
   vpc_id = aws_vpc.vpc.id
   route {
      cidr_block = "0.0.0.0/0"
      gateway_id = aws_nat_gateway.nat_gateway1.id
   }
   tags = {
      Name = "NAT-route-table1"
   }
}

resource "aws_route_table" "NAT_route_table2" {
   depends_on = [
      aws_vpc.vpc,
      aws_nat_gateway.nat_gateway2,
   ]
   vpc_id = aws_vpc.vpc.id
   route {
      cidr_block = "0.0.0.0/0"
      gateway_id = aws_nat_gateway.nat_gateway2.id
   }
   tags = {
      Name = "NAT-route-table2"
   }
}

# We associate our route table to the private subnet
# Keeps the subnet private because it has a route to the internet via our NAT gateway 
resource "aws_route_table_association" "associate_routetable_to_private_subnet1" {
   depends_on = [
      aws_subnet.private_subnet1,
      aws_route_table.NAT_route_table1,
   ]
   subnet_id = aws_subnet.private_subnet1.id
   route_table_id = aws_route_table.NAT_route_table1.id
}

resource "aws_route_table_association" "associate_routetable_to_private_subnet2" {
   depends_on = [
      aws_subnet.private_subnet2,
      aws_route_table.NAT_route_table2,
   ]
   subnet_id = aws_subnet.private_subnet2.id
   route_table_id = aws_route_table.NAT_route_table2.id
}

# We create a security group for SSH traffic
# EC2 instances' firewall that controls incoming and outgoing traffic
resource "aws_security_group" "sg_bastion_host" {
   depends_on = [
      aws_vpc.vpc,
   ]
   name = "sg bastion host"
   description = "bastion host security group"
   vpc_id = aws_vpc.vpc.id
   ingress {
      description = "allow ssh"
      from_port = 22
      to_port = 22
      protocol = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
   }
   egress {
      from_port = 0
      to_port = 0
      protocol = "-1"
      cidr_blocks = ["0.0.0.0/0"]
   }
   tags = {
      Name = "sg bastion host"
   }
}

# We create an elastic IP 
# A static public IP address that we can assign to our bastion host
resource "aws_eip" "bastion_elastic_ip1" {
   vpc = true
}

resource "aws_eip" "bastion_elastic_ip2" {
   vpc = true
}

# We create an ssh key using the RSA algorithm with 4096 rsa bits
# The ssh key always includes the public and the private key
resource "tls_private_key" "ssh_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

# We upload the public key of our created ssh key to AWS
resource "aws_key_pair" "public_ssh_key" {
  key_name   = var.public_key_name
  public_key = tls_private_key.ssh_key.public_key_openssh

   depends_on = [tls_private_key.ssh_key]
}

# We save our public key at our specified path.
# Can upload on remote server for ssh encryption
resource "local_file" "save_public_key" {
  content = tls_private_key.ssh_key.public_key_openssh 
  filename = "${var.key_path}${var.public_key_name}.pem"
}

# We save our private key at our specified path.
# Allows private key instead of a password to securely access our instances
resource "local_file" "save_private_key" {
  content = tls_private_key.ssh_key.private_key_pem
  filename = "${var.key_path}${var.private_key_name}.pem"
}

# We create a bastion host
# Allows SSH into instances in private subnet
resource "aws_instance" "bastion_host1" {
   depends_on = [
      aws_security_group.sg_bastion_host,
   ]
   ami = "ami-077e31c4939f6a2f3"
   instance_type = "t2.micro"
   key_name = aws_key_pair.public_ssh_key.key_name
   vpc_security_group_ids = [aws_security_group.sg_bastion_host.id]
   subnet_id = aws_subnet.public_subnet1.id
   tags = {
      Name = "bastion host 1"
   }
   provisioner "file" {
    source      = "${var.key_path}${var.private_key_name}.pem"
    destination = "/home/ec2-user/private_ssh_key.pem"

    connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.ssh_key.private_key_pem
    host     = aws_instance.bastion_host1.public_ip
    }
  }
}

# We associate the elastic ip to our bastion host
resource "aws_eip_association" "bastion_eip_association1" {
  instance_id   = aws_instance.bastion_host1.id
  allocation_id = aws_eip.bastion_elastic_ip1.id
}

resource "aws_instance" "bastion_host2" {
   depends_on = [
      aws_security_group.sg_bastion_host,
   ]
   ami = "ami-077e31c4939f6a2f3"
   instance_type = "t2.micro"
   key_name = aws_key_pair.public_ssh_key.key_name
   vpc_security_group_ids = [aws_security_group.sg_bastion_host.id]
   subnet_id = aws_subnet.public_subnet2.id
   tags = {
      Name = "bastion host 2"
   }
   provisioner "file" {
    source      = "${var.key_path}${var.private_key_name}.pem"
    destination = "/home/ec2-user/private_ssh_key.pem"

    connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.ssh_key.private_key_pem
    host     = aws_instance.bastion_host2.public_ip
    }
  }
}

# We associate the elastic ip to our bastion host
resource "aws_eip_association" "bastion_eip_association2" {
  instance_id   = aws_instance.bastion_host2.id
  allocation_id = aws_eip.bastion_elastic_ip2.id
}

# We save our bastion host ip in a file.
resource "local_file" "ip_addresses" {
  content = <<EOF
            Bastion host 1 public ip address: ${aws_eip.bastion_elastic_ip1.public_ip}
            Bastion host 1 private ip address: ${aws_instance.bastion_host1.private_ip}
            Bastion host 2 public ip address: ${aws_eip.bastion_elastic_ip2.public_ip}
            Bastion host 2 private ip address: ${aws_instance.bastion_host2.private_ip}
  EOF
  filename = "${var.key_path}ip_addresses.txt"
}
