#!/bin/bash -x


#if [ $# -ne 2 ] ; then
#    echo "\
#      Usage: $(basename $0) target_iam_account target_region [iam_role_path]
#      " >&2
#    exit 1
#fi

iam_account=${1:-''}
region=${2:-''}
iam_role_path=${3:-'./saltstack/iam-role-ec2-lambda.json'}


cat > ${iam_role_path} << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:CreateTags",
                "ec2:DescribeInstances",
                "ec2:DescribeTags"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": "logs:CreateLogGroup",
            "Resource": "arn:aws:logs:${region}:${iam_account}:*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": [
                "arn:aws:logs:${region}:${iam_account}:log-group:/aws/lambda/*"
            ]
        }
    ]
}
EOF

echo "IAM Role generated to: ${iam_role_path}"
