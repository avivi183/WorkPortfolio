# Configure AWS Provider
provider "aws" {
	region = "eu-west-1"
}

# VPC with Subnets
resource "aws_vpc" "VPC1" {
	cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "Subnet1" {
	vpc_id     = aws_vpc.VPC1.id
	cidr_block = "10.0.1.0/24"
	availability_zone = "eu-west-1a"
}

resource "aws_subnet" "Subnet2" {
	vpc_id     = aws_vpc.VPC1.id
	cidr_block = "10.0.2.0/24"
	availability_zone = "eu-west-1a"
}

# S3 logs bucket
resource "aws_s3_bucket" "s3logs-avivsplayground" {
	bucket = "s3logs-avivsplayground"
}

# S3 logs bucket policy
resource "aws_s3_bucket_policy" "s3logs-bucketpolicy" {
	bucket = aws_s3_bucket.s3logs-avivsplayground.id
	policy = data.aws_iam_policy_document.s3logs-bucketpolicy.json
}

data "aws_iam_policy_document" "s3logs-bucketpolicy" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::s3logs-avivsplayground/*"]
    effect    = "Allow"
    principals {
      type = "AWS"
      identifiers = ["arn:aws:iam::982081089729:user/terraform-user"]
    }
  }
}

# S3 Bucket
resource "aws_s3_bucket" "s3-avivsplayground" {
	bucket = "s3-avivsplayground"
}

# S3 Server-side encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "s3-bucket-sse" {
	bucket = aws_s3_bucket.s3-avivsplayground.id
	rule {
		apply_server_side_encryption_by_default {
		sse_algorithm = "AES256" 
		}
	}
}

# S3 bucket logging function enabling
resource "aws_s3_bucket_logging" "s3-logging" {
	bucket = aws_s3_bucket.s3-avivsplayground.id
	target_bucket = "s3logs-avivsplayground"
	target_prefix = "s3-avivsplayground/"
}

#S3 IAM policy creation
resource "aws_iam_policy" "s3-iampolicy" {
	name = "s3-iampolicy"
	policy = <<EOF
	{
		"Version": "2012-10-17",
		"Statement": [
		{
			"Effect": "Allow",
			"Action": [
				"s3:GetObject",
				"s3:PutObject",
				"s3:ListBucket"
				],
			"Resource": [
			"arn:aws:s3:::s3-avivsplayground/*" 
				]
			}
		]
	}
	EOF
}

#Creating group and attaching S3 with IAM policy
resource "aws_iam_group" "group1" {
	name = "group1"
}

resource "aws_iam_group_policy_attachment" "s3-iampolicyattachment" {
	group = aws_iam_group.group1.name
	policy_arn = aws_iam_policy.s3-iampolicy.arn
}

#Creating users and assigning them to the group
resource "aws_iam_user" "user1" {
	name = "user1"
}

resource "aws_iam_user" "user2" {
  name = "user2"
}

resource "aws_iam_user_group_membership" "user1_membership" {
	user = aws_iam_user.user1.name
	groups = [
		aws_iam_group.group1.name
	]
}

resource "aws_iam_user_group_membership" "user2_membership" {
	user = aws_iam_user.user2.name
	groups = [
		aws_iam_group.group1.name
	]
}

# Windows VM1
resource "aws_instance" "Windows-VM" {
	ami           = "ami-00b19da53e9b57a30"
	instance_type = "t3.micro"
	subnet_id     = aws_subnet.Subnet1.id
	vpc_security_group_ids = [aws_security_group.restricted-sg.id]
	root_block_device {
		volume_type = "gp2" 
		volume_size = 30
		encrypted  = true 
	}
}

# Ubuntu VM2
resource "aws_instance" "Ubuntu-VM" {
	ami           = "ami-03fd334507439f4d1"
	instance_type = "t2.micro"
	subnet_id     = aws_subnet.Subnet2.id
	vpc_security_group_ids = [aws_security_group.restricted-sg.id]
	root_block_device {
		volume_type = "gp2"
		volume_size = 30
		encrypted  = true 
	}
}

# Security Group (restircted)
resource "aws_security_group" "restricted-sg" {
	name        = "restricted_sg"
	description = "Security Group for all EC2 instances with access only from inside internal subnets"
	vpc_id      = aws_vpc.VPC1.id

  	ingress {
   		from_port   = 3389
    		to_port     = 3389
   		protocol    = "tcp"
    		cidr_blocks = ["10.0.1.0/24","10.0.2.0/24"]  # Allow RDP from internal subnets
	}
	ingress {
   		from_port   = 22
    		to_port     = 22
   		protocol    = "tcp"
    		cidr_blocks = ["10.0.1.0/24","10.0.2.0/24"]  # Allow SSH from internal subnets
	}
	egress {
		from_port   = 0
		to_port     = 0
		protocol    = "-1"
		cidr_blocks = ["0.0.0.0/0"]  # Allow all outbound traffic
	}
}