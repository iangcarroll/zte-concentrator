# AWS Los Angeles Local Zone deployment

`deploy/aws-local-zone-lax.yaml` runs one `icgd` instance in the Los Angeles
Local Zone. The default is `us-west-2-lax-1a`; `us-west-2-lax-1b` is also
supported. Unlike the Verizon Wavelength Zone, a Local Zone Elastic IP accepts
ordinary internet ingress, so devices on T-Mobile and other carriers can reach
the concentrator.

The stack is intentionally isolated:

- a dedicated VPC and Local Zone subnet;
- one internet gateway and a stable Elastic IP advertised from LAX;
- no SSH ingress; management uses AWS Systems Manager Session Manager;
- only TCP `10088` and UDP `10000-10003` are admitted;
- a required device-MAC allowlist;
- proxy egress denies loopback, link-local, and every RFC1918 range;
- T3 CPU credits use `standard`, avoiding unlimited-mode credit charges; and
- the 8 GB encrypted root volume uses `gp3`.

The bootstrap checks out and builds an exact, GitHub-reachable 40-character
commit. A branch name is deliberately not accepted: knowing which binary is
live matters more than following `main` automatically.

## Graviton availability

The live EC2 offerings API was checked after opting in on 2026-08-25. Neither
Los Angeles zone offered any Graviton instance: there was no `t4g`, `m6g`,
`c6g`, `m7g`, `c7g`, `m8g`, or `c8g` offering. The AWS price catalog still
contains an `m6g.xlarge` Los Angeles SKU, but a catalog SKU is not proof that an
account can launch the type. The template therefore uses an actually offered
x86 `t3.medium` and an x86 Amazon Linux 2023 AMI.

The `t3.medium` has a documented 256 Mbps baseline and 5 Gbps burst network
bandwidth. The smaller `t3.small` has only a 128 Mbps baseline, which leaves too
little margin for a requirement to sustain 100 Mbps after ICG framing and TCP/IP
overhead. Instance bandwidth is only one boundary; prove the complete path from
a suitably fast client before relying on that rate.

Re-run this before considering an architecture change:

```sh
AWS_PROFILE=cautela aws ec2 describe-instance-type-offerings \
  --region us-west-2 --location-type availability-zone \
  --query "sort_by(InstanceTypeOfferings[?starts_with(Location, 'us-west-2-lax-1') && contains(InstanceType, 'g')],&InstanceType)[].{Zone:Location,Type:InstanceType}" \
  --output table
```

## Deploy

The `us-west-2-lax-1` Local Zone group must already be opted in. The stack
requires capability acknowledgement because it creates an SSM-only EC2 role:

```sh
AWS_PROFILE=cautela aws cloudformation deploy \
  --region us-west-2 \
  --stack-name zte-concentrator-lax \
  --template-file deploy/aws-local-zone-lax.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    SourceCommit="$(git rev-parse HEAD)" \
    AllowedDevices='<eth0 MAC from the ICG handshake>'
```

Creating the stack does not touch a device. The device's coordinator override
and physical aggregation switch remain separate actions.

## Verify

Get the instance and public IP without printing the MAC allowlist parameter:

```sh
instance_id=$(AWS_PROFILE=cautela aws cloudformation describe-stacks \
  --region us-west-2 --stack-name zte-concentrator-lax \
  --query 'Stacks[0].Outputs[?OutputKey==`InstanceId`].OutputValue' --output text)

AWS_PROFILE=cautela aws ec2 describe-instances --region us-west-2 \
  --instance-ids "$instance_id" \
  --query 'Reservations[0].Instances[0].{State:State.Name,Type:InstanceType,Zone:Placement.AvailabilityZone,PublicIP:PublicIpAddress}'

AWS_PROFILE=cautela aws ssm send-command --region us-west-2 \
  --instance-ids "$instance_id" --document-name AWS-RunShellScript \
  --parameters 'commands=["systemctl is-active icgd","icgd -version","ss -lntu"]'
```

For a sustained test through the ICG framing, reassembly, and proxy path, use a
large plain-HTTP object whose exact size is known:

```sh
bin/icg-probe -server "$public_ip:10088" -udp "$public_ip:10000" \
  -udp-legs 4 -legs 3 -mac '<allowed test MAC>' \
  -benchmark 'http://speed-source.example/large.bin' \
  -benchmark-bytes 100000000 -benchmark-min-mbps 100 \
  -benchmark-runs 5 -timeout 60s
```

This is end-to-end: a slow client access network will cap the result even when
the EC2 instance has spare capacity. Use a client connection known to exceed
the target before treating a failure as an instance-sizing result.

The deployed `t3.medium` was validated on 2026-08-25 from a temporary
`us-west-2` EC2 client. Five sequential responses of approximately 100 MB each
passed through three ICG TCP legs and measured 717, 591, 863, 840, and 858
Mbit/s. All protocol checks passed with no framing resyncs or dropped input. The
temporary client stack was deleted after the test.

The observability UI remains on loopback. Use Session Manager port forwarding
instead of opening another public listener.

## Cost and teardown

At the catalog prices checked on 2026-08-25, the default stack is approximately
`$40.85/month` before data transfer:

- `t3.medium`: `$36.43/month` at 730 hours;
- 8 GB `gp3`: `$0.77/month`; and
- one public IPv4: approximately `$3.65/month`.

Internet egress and any T3 surplus CPU credits are billed separately. Delete
the whole experiment with one stack operation:

```sh
AWS_PROFILE=cautela aws cloudformation delete-stack \
  --region us-west-2 --stack-name zte-concentrator-lax
```

CloudFormation owns the instance, volume, Elastic IP, security group, subnet,
routes, internet gateway, VPC, and IAM role/profile so teardown does not depend
on reconstructing individually created resources.
