terraform {
  /*backend "s3" {
    bucket         = "project-2-terraform-state"
    key            = "terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    use_lockfile = true
    dynamodb_table = "state-locking"
  }*/
}

resource "aws_cloudformation_stack" "cloud_formation_stack" {
  name = "cloud-formation-terraform-state"

  template_body = jsonencode({
    "Resources" : {
      "MyS3Bucket" : {
        "Type" : "AWS::S3::Bucket",
        "Properties" : {
          "BucketName" : "project-2-terraform-state",
          "VersioningConfiguration" : {
            "Status" : "Enabled"
          },
          "PublicAccessBlockConfiguration" : {
            "BlockPublicAcls" : true,
            "IgnorePublicAcls" : true,
            "BlockPublicPolicy" : true,
            "RestrictPublicBuckets" : true
          },
          "BucketEncryption" : {
            "ServerSideEncryptionConfiguration" : [
              {
                "ServerSideEncryptionByDefault" : {
                  "SSEAlgorithm" : "AES256"
                }
              }
            ]
          }
        }
      },
      "DynamoDBTable" : {
        "Type" : "AWS::DynamoDB::Table",
        "Properties" : {
          "TableName" : "state-locking",
          "AttributeDefinitions" : [
            {
              "AttributeName" : "LockID",
              "AttributeType" : "S"
            }
          ],
          "KeySchema" : [
            {
              "AttributeName" : "LockID",
              "KeyType" : "HASH"
            }
          ],
          "ProvisionedThroughput" : {
            "ReadCapacityUnits" : 5,
            "WriteCapacityUnits" : 5
          }
        }
      }
    },
    "Outputs" : {
      "TerraformStateBucket" : {
        "Value" : { "Ref" : "MyS3Bucket" },
        "Description" : "Name of S3 bucket created for backend"
      },
      "TerraformLockTable" : {
        "Value" : { "Ref" : "DynamoDBTable" },
        "Description" : "Name of DynamoDB Table created for locking"
      }
    }
  })
}

data "tls_certificate" "github" {
  url = "https://token.actions.githubusercontent.com/.well-known/openid-configuration"
}

resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]

  thumbprint_list = [data.tls_certificate.github.certificates[0].sha1_fingerprint]
}

resource "aws_iam_role" "github_actions_role" {
  name = "github-actions-terraform-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Federated" : aws_iam_openid_connect_provider.github.arn
        },
        "Action" : "sts:AssumeRoleWithWebIdentity",
        "Condition" : {
          "StringLike" : {
            "token.actions.githubusercontent.com:sub" : [
              "repo:boubakarbd/Project2-Deploy-to-Beanstalk-Infrastructure-as-Code:refs:heads/main",
              "repo:boubakarbd/Project2-Deploy-to-Beanstalk-AppCode:refs:heads/main"
            ]
          },
          "StringEquals" : {
            "token.actions.githubusercontent.com:aud" : "sts.amazonaws.com"
          }
        }
      }

    ]
  })
}

resource "aws_iam_policy" "terraform-deployment-policy" {
  name        = "terraform-deployment-policy"
  description = "Politique restrictive pour le déploiement de l'infrastructure Projet 2"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Permissions pour gérer l'infrastructure Beanstalk et RDS
        Effect = "Allow"
        Action = [
          "elasticbeanstalk:*",
          "rds:*",
          "ec2:Describe*",
          "ec2:CreateSecurityGroup",
          "ec2:DeleteSecurityGroup",
          "autoscaling:*",
          "elasticloadbalancing:*"
        ]
        Resource = "*" 
      },
      {
        # Restriction spécifique sur S3 (Backend et Artefacts)
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:GetBucketLocation"
        ]
        Resource = [
          aws_s3_bucket.bucket-project2-appcode.arn,
          "${aws_s3_bucket.bucket-project2-appcode.arn}/*",
          "arn:aws:s3:::project-2-terraform-state",
          "arn:aws:s3:::project-2-terraform-state/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "github-actions-role-attachment" {
  role       = aws_iam_role.github_actions_role.name
  policy_arn = aws_iam_policy.terraform-deployment-policy.arn

}

output "terraform_state_bucket" {
  value = aws_cloudformation_stack.cloud_formation_stack.outputs["TerraformStateBucket"]
}

output "terraform_lock_table" {
  value = aws_cloudformation_stack.cloud_formation_stack.outputs["TerraformLockTable"]
}
resource "aws_vpc" "vpc" {
  cidr_block = "10.0.0.0/16"
}
resource "aws_route_table" "route_table" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id
}

resource "aws_subnet" "public-subnet1" {
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true
}

resource "aws_subnet" "public-subnet2" {
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "us-east-1b"
  map_public_ip_on_launch = true
}

resource "aws_subnet" "private-subnet1" {
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = "10.0.3.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = false
}

resource "aws_subnet" "private-subnet2" {
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = "10.0.4.0/24"
  availability_zone       = "us-east-1b"
  map_public_ip_on_launch = false
}

resource "aws_route_table_association" "public_subnet1" {
  subnet_id      = aws_subnet.public-subnet1.id
  route_table_id = aws_route_table.route_table.id
}

resource "aws_route_table_association" "public_subnet2" {
  subnet_id      = aws_subnet.public-subnet2.id
  route_table_id = aws_route_table.route_table.id
}


resource "aws_eip" "nat_eip1" {
  domain = "vpc"
}

resource "aws_eip" "nat_eip2" {
  domain = "vpc"
}

resource "aws_nat_gateway" "nat_gw1" {
  allocation_id = aws_eip.nat_eip1.id
  subnet_id     = aws_subnet.public-subnet1.id
}

resource "aws_nat_gateway" "nat_gw2" {
  allocation_id = aws_eip.nat_eip2.id
  subnet_id     = aws_subnet.public-subnet2.id
}

resource "aws_route_table" "private-rt1" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat_gw1.id
  }
}

resource "aws_route_table" "private-rt2" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat_gw2.id
  }
}

resource "aws_route_table_association" "private_subnet1" {
  subnet_id      = aws_subnet.private-subnet1.id
  route_table_id = aws_route_table.private-rt1.id
}

resource "aws_route_table_association" "private_subnet2" {
  subnet_id      = aws_subnet.private-subnet2.id
  route_table_id = aws_route_table.private-rt2.id
}

resource "aws_security_group" "alb-sg" {
  name   = "alb-sg"
  vpc_id = aws_vpc.vpc.id
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "beanstalk-sg" {
  name   = "beanstalk-sg"
  vpc_id = aws_vpc.vpc.id

  ingress {
    from_port       = 5000
    to_port         = 5000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb-sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "rds-sg" {
  name   = "rds-sg"
  vpc_id = aws_vpc.vpc.id

  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.beanstalk-sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }



}

resource "aws_db_subnet_group" "rds-subnet-group" {
  name       = "rds-subnet-group"
  subnet_ids = [aws_subnet.private-subnet1.id, aws_subnet.private-subnet2.id]

}

resource "aws_db_parameter_group" "rds-parameter-group" {
  name        = "rds-parameter-group"
  family      = "mysql8.0"
  description = "Custom parameter group for RDS MySQL 8.0"

  parameter {
    name  = "max_connections"
    value = "200"
  }

  lifecycle {
    create_before_destroy = true
  }

}

resource "aws_db_instance" "rds-instance" {
  identifier              = "project2-rds-instance"
  engine                  = "mysql"
  engine_version          = "8.0"
  instance_class          = "db.t3.micro"
  db_subnet_group_name    = aws_db_subnet_group.rds-subnet-group.name
  parameter_group_name    = aws_db_parameter_group.rds-parameter-group.name
  vpc_security_group_ids  = [aws_security_group.rds-sg.id]
  allocated_storage       = 20
  username                = "admin"
  password                = var.db_password
  skip_final_snapshot     = true
  backup_retention_period = 7
}

resource "aws_s3_bucket" "bucket-project2-appcode" {
  bucket = "project-2-app-code-bucket-unique-name-2026-01"
}

resource "aws_s3_bucket_versioning" "bucket-project2-appcode-versioning" {
  bucket = aws_s3_bucket.bucket-project2-appcode.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_kms_key" "key-appcode-bucket" {
  description             = "KMS key for encrypting S3 bucket for app code"
  deletion_window_in_days = 20
}

resource "aws_s3_bucket_server_side_encryption_configuration" "bucket-project2-appcode-encryption" {
  bucket = aws_s3_bucket.bucket-project2-appcode.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.key-appcode-bucket.arn
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "bucket-project2-appcode-lifecycle" {
  bucket = aws_s3_bucket.bucket-project2-appcode.id

  rule {
    id     = "Expire old versions"
    status = "Enabled"

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

resource "aws_iam_policy" "s3bucket-artefact-policy" {
  name        = "s3bucket-artifact-policy"
  description = "Policy to allow Beanstalk to access S3 bucket for app code"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetBucketLocation",
          "kms:GenerateDataKey",
          "kms:Decrypt",
        ]
        Resource = [
          aws_s3_bucket.bucket-project2-appcode.arn,
          "${aws_s3_bucket.bucket-project2-appcode.arn}/*",
          aws_kms_key.key-appcode-bucket.arn
        ]
      }
    ]
  })

}

resource "aws_iam_role_policy_attachment" "beanstalk-s3bucket-attachment" {
  role       = aws_iam_role.github_actions_role.name
  policy_arn = aws_iam_policy.s3bucket-artefact-policy.arn
}


resource "aws_iam_role" "ec2-instance-beanstalk-role" {
  name = "ec2-instance-beanstalk-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
  
}


resource "aws_iam_instance_profile" "ec2-instance-beanstalk-profile" {
  name = "ec2-instance-beanstalk-profile"
  role = aws_iam_role.ec2-instance-beanstalk-role.name
}

resource "aws_iam_role_policy_attachment" "eb-web-tier" {
  role       = aws_iam_role.ec2-instance-beanstalk-role.name
  policy_arn = "arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"
}

resource "aws_iam_role_policy_attachment" "eb-worker-tier" {
  role       = aws_iam_role.ec2-instance-beanstalk-role.name
  policy_arn = "arn:aws:iam::aws:policy/AWSElasticBeanstalkWorkerTier"
}

resource "aws_iam_role_policy_attachment" "eb-docker" {
  role       = aws_iam_role.ec2-instance-beanstalk-role.name
  policy_arn = "arn:aws:iam::aws:policy/AWSElasticBeanstalkMulticontainerDocker"
}


resource "aws_elastic_beanstalk_application" "beanstalk-application" {
  name        = "project2-beanstalk-application"
  description = "Elastic Beanstalk application for Project 2"
}

resource "aws_elastic_beanstalk_environment" "beanstalk-environment" {
  name                = "project2-beanstalk-environment"
  application         = aws_elastic_beanstalk_application.beanstalk-application.name
  solution_stack_name = "64bit Amazon Linux 2023 v5.4.6 running Tomcat Corretto 17"

  setting {
    namespace = "aws:autoscaling:launchconfiguration"
    name      = "IamInstanceProfile"
    value     = aws_iam_instance_profile.ec2-instance-beanstalk-profile.name
  }

  setting {
    namespace = "aws:ec2:vpc"
    name      = "VPCId"
    value     = aws_vpc.vpc.id
  }

  setting {
    namespace = "aws:ec2:vpc"
    name      = "Subnets"
    value     = "${aws_subnet.private-subnet1.id},${aws_subnet.private-subnet2.id}"
  }

  setting {
    namespace = "aws:ec2:vpc"
    name      = "ELBSubnets"
    value     = "${aws_subnet.public-subnet1.id},${aws_subnet.public-subnet2.id}"
  }

  setting {
    namespace = "aws:elasticbeanstalk:environment"
    name = "LoadBalancerType"
    value = "application"
  }

  setting {
    namespace = "aws:autoscaling:asg"
    name = "MinSize"
    value = "1"
  }

  setting {
    namespace = "aws:autoscaling:asg"
    name = "MaxSize"
    value = "3"
  }

  setting {
    namespace = "aws:autoscaling:launchconfiguration"
    name = "SecurityGroups"
    value = aws_security_group.beanstalk-sg.id
  }

  setting {
    namespace = "aws:elasticbeanstalk:application:environment"
    name      = "JDBC_CONNECTION_STRING"
    value     = "jdbc:mysql://${aws_db_instance.rds-instance.endpoint}/project2db"
  }
  setting {
    namespace = "aws:elasticbeanstalk:application:environment"
    name      = "RDS_USERNAME"
    value     = aws_db_instance.rds-instance.username
  }
  setting {
    namespace = "aws:elasticbeanstalk:application:environment"
    name      = "RDS_PASSWORD"
    value     = var.db_password
  }

  setting {
    namespace = "aws:elbv2:listener:80"
    name = "Rules"
    value = "cloudfront-only"
  }

  setting {
    namespace = "aws:elbv2:listenerrule:cloudfront-only"
    name = "HttpHeaderConfig"
    value = "{\"X-Custom-Header\":[\"${var.custom_header_value}\"]}"
  }

  setting {
    namespace = "aws:elbv2:listenerrule:cloudfront-only"
    name = "Process"
    value = "default"
  }

  setting {
    namespace = "aws:elbv2:listener:80"
    name = "DefaultProcess"
    value = "forbidden"
  }




  
}

resource "aws_cloudfront_distribution" "app_distribution" {
  origin {
    
    domain_name = aws_elastic_beanstalk_environment.beanstalk-environment.cname
    origin_id   = "Beanstalk-ALB"

    custom_header {
      name  = "X-Custom-Header"
      value = var.custom_header_value # Gardez cette valeur privée
    }

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "http-only" # Beanstalk écoute souvent en HTTP par défaut
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = ""

  
  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "Beanstalk-ALB"

    forwarded_values {
      query_string = true 
      headers      = ["Host", "Origin", "Authorization"] # Crucial pour Spring Security
      cookies {
        forward = "all" # Nécessaire pour les sessions JSESSIONID de Tomcat
      }
    }

    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

resource "aws_iam_policy" "cloudwatch-logs-policy" {
  name        = "cloudwatch-logs-policy"
  description = "Restricted security policy only allowing the creation of log groups/streams and the sending of events to CloudWatch, with no modification or deletion rights."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "arn:aws:logs:*:*:log-group:/aws/elasticbeanstalk/*"
      }
    ]
  })
  
}

resource "aws_iam_role_policy_attachment" "cloudwatch-logs-policy-attachment" {
  role       = aws_iam_role.ec2-instance-beanstalk-role.name
  policy_arn = aws_iam_policy.cloudwatch-logs-policy.arn
  
}

resource "aws_cloudwatch_metric_alarm" "high-cpu-alarm" {
  alarm_name          = "HighCPUUtilization"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"

  dimensions = {
    AutoScalingGroupName = aws_elastic_beanstalk_environment.beanstalk-environment.autoscaling_groups[0]
  }

  alarm_description = "This metric monitors EC2 CPU utilization and triggers if it exceeds 80% for two consecutive periods of 5 minutes."
  actions_enabled   = true
  alarm_actions = [aws_sns_topic.high-cpu-alarm-topic.arn]
}

resource "aws_sns_topic_subscription" "high-cpu-alarm-subscription" {
  topic_arn = aws_sns_topic.high-cpu-alarm-topic.arn
  protocol  = "email"
  endpoint  = var.alarm_email_endpoint
}

resource "aws_sns_topic" "high-cpu-alarm-topic" {
  name = "beanstalk-alerts-topic"
}

resource "aws_cloudwatch_dashboard" "beanstalk_app_dashboard" {
  dashboard_name = "Beanstalk-App-Dashboard"

  dashboard_body = jsonencode({
    widgets = [
      # Premier widget : Utilisation CPU
      {
        type = "metric"
        x    = 0
        y    = 0
        width = 12
        height = 6
        properties = {
          metrics = [
            [ "AWS/EC2", "CPUUtilization", "AutoScalingGroupName", "${aws_elastic_beanstalk_environment.beanstalk-environment.autoscaling_groups[0]}" ]
          ]
          period = 300
          stat   = "Average"
          region = "us-east-1"
          title  = "EC2 Instance CPU Utilization"
        }
      },
      # Deuxième widget : Santé applicative (Trafic vs Erreurs)
      {
        type = "metric",
        x = 12, // Placé à droite du premier widget (qui fait 12 de large)
        y = 0,
        width = 12,
        height = 6,
        properties = {
          metrics = [
            [ "AWS/ElasticBeanstalk", "RequestsTotal", "EnvironmentName", "${aws_elastic_beanstalk_environment.beanstalk-environment.name}", { "stat": "Sum", "label": "Total Requêtes" } ],
            [ ".", "Requests5xx", ".", ".", { "stat": "Sum", "label": "Erreurs 5xx (Serveur)", "color": "#d62728" } ]
          ],
          period = 300,
          region = "eu-west-3",
          title = "Santé de l'Application (Trafic vs Erreurs)"
        }
      }

    ]
  })
}

resource "aws_iam_policy" "cloudwatch_monitoring_policy" {
  name        = "CloudWatchMonitoringPolicy"
  description = "Autorise l'envoi de logs et de métriques personnalisées (RAM) vers CloudWatch"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # --- PARTIE 1 : LOGS (Moindre privilège conservé) ---
      {
        Effect   = "Allow"
        Action   = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "arn:aws:logs:*:*:log-group:/aws/elasticbeanstalk/*"
      },
      # --- PARTIE 2 : MÉTRIQUES (Nouveau pour la RAM) ---
      {
        Effect   = "Allow"
        Action   = [
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "cloudwatch-monitoring-policy-attachment" {
  role       = aws_iam_role.ec2-instance-beanstalk-role.name
  policy_arn = aws_iam_policy.cloudwatch_monitoring_policy.arn
}

