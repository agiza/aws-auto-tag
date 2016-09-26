# aws-auto-tag
Auto tagging AWS resources with `python` and `saltstack`.
Based on the idea of http://blog.gorillastack.com/wp-content/uploads/2015/09/Multi-account-auto-tag-diagram-1002x1024.png



## Cloudtrail supported services (for taggable resources)

- Elastic Block Store (Amazon EBS)
- ElastiCache (ElastiCache)
- Elastic Compute Cloud (Amazon EC2)
- Elastic Load Balancing
- EMR
- Glacier
- Kinesis
- Redshift
- Amazon Relational Database Service (Amazon RDS)
- Amazon Route 53
- Amazon S3 bucket level event
- Amazon Virtual Private Cloud (Amazon VPC)
- Auto Scaling
- AWS CloudFormation
- AWS Elastic Beanstalk


## Auto-tag supported services

- EC2 Instances



## TO-DO List

- Automatic Deployment
  - Activate cloudtrail with proper configuration
  - Configure s3 buckets
  - Deploy lambda and configure firing events
  - Extend services Support
