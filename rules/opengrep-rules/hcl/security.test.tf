# Annotated tests for hcl/security.yaml (generic regex rule).
resource "aws_security_group" "bad" {
  ingress {
    # ruleid: scp.hcl.aws.sg-open-ingress
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "good" {
  ingress {
    # ok: scp.hcl.aws.sg-open-ingress
    cidr_blocks = ["10.0.0.0/8"]
  }
}
