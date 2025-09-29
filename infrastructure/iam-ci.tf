# Allow CI user to read specific SSM parameters Terraform needs
resource "aws_iam_policy" "ci_ssm_read" {
  name        = "crossfeed-deploy-staging-ssm-read"
  description = "Allow CI to read VPC/subnet SSM parameters used by Terraform"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Sid    = "ReadParameterStoreValues",
      Effect = "Allow",
      Action = [
        "ssm:GetParameter",
        "ssm:GetParameters",
        "ssm:GetParametersByPath"
      ],
      Resource = [
        "arn:aws:ssm:us-east-1:957221700844:parameter/LZ/VPC_CIDR_BLOCK",
        "arn:aws:ssm:us-east-1:957221700844:parameter/LZ/SUBNET_ENDPOINT_A_ID",
        "arn:aws:ssm:us-east-1:957221700844:parameter/LZ/SUBNET_ENDPOINT_B_ID",
        "arn:aws:ssm:us-east-1:957221700844:parameter/LZ/SUBNET_ENDPOINT_C_ID",
        "arn:aws:ssm:us-east-1:957221700844:parameter/LZ/VPC_ID"
      ]
    }]
  })
}

resource "aws_iam_user_policy_attachment" "ci_ssm_read_attach" {
  # mirror whatever conditional you use for staging, if needed
  user       = "crossfeed-deploy-staging"
  policy_arn = aws_iam_policy.ci_ssm_read.arn
}