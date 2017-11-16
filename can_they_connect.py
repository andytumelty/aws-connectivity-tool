#!/usr/bin/env python3  
import argparse
import boto3
import re
import configparser
import os
import logging
import ipaddress
import json
import pprint

# def get_resource_from_identifier(identifier):
#     # TODO explicitly define connectivity scenarios
#     # given an account/ip determine instance id
#     # given a domain name, determine IP -> is that a LB? etc etc
#     # for now, identifier must be AWS instance id
#     return identifier

logging.basicConfig(format='%(levelname)s,%(message)s')
logger = logging.getLogger('default')
logger.setLevel(logging.DEBUG)

logging.getLogger('boto3').setLevel(logging.INFO)

def get_boto_session(account):
    # tries to work out what is meant by account, and return a relevant boto session
    # checks the following: entry in can_they_connect.cfg (using aws_shared_credentials_file or aws_access_key_id and
    # aws_secret_access_key parameters), a profile name in the default session
    account_config = configparser.ConfigParser()
    account_config.read('can_they_connect.cfg')
    # if is in accounts.cfg
    s = None
    if account in account_config.sections():
        logger.debug('account in can_they_connect.cfg, using config')
        if 'aws_shared_credentials_file' in account_config[account]:
            logger.debug('found aws_shared_credentials_file in config')
            creds_file = configparser.ConfigParser()
            creds_file.read(os.path.expanduser(account_config[account]['aws_shared_credentials_file']))
            s = boto3.session.Session(
                aws_access_key_id=creds_file['default']['aws_access_key_id'],
                aws_secret_access_key=creds_file['default']['aws_secret_access_key']
            )
        elif {'aws_access_key_id', 'aws_secret_access_key'} <= set(account_config[account].keys()):
            logger.debug('found aws_access_key_id and aws_secret_access_key in config')
            s = boto3.session.Session(
                    aws_access_key_id=account_config[account]['aws_access_key_id'],
                    aws_secret_access_key=account_config[account]['aws_secret_access_key']
            )
        else:
            raise Exception('unable to parse account credentials in can_they_connect.cfg')
    else:
        s = boto3.session.Session()
        if account in s.available_profiles:
            logger.debug('found account in profile for default session')
            s = boto3.session.Session(profile_name=account)

    if s is None:
        raise Exception("Unable to create session with account %s" % account)
    else:
        return s


def get_resource(resource, session):
    # given a resource identifier, returns appropriate boto3 resource
    # current implementations:
    # - EC2 instance from instance ID
    # - EC2 instance from IP
    # (possible) future implementations:
    # - ELB
    # - Security group
    # - CIDR block
    # - External connection
    # - DNS
    # - instance by tag

    # EC2 Instance
    logger.debug("finding resource %s" % resource)
    if resource.split('-', 1)[0] == 'i':
        logger.debug("found instance %s" % resource)
        return session.resource('ec2').Instance(resource)
    # IP address, for now assume EC2 instance
    # FIXME this will match on external IPs, and non-valid ones like 500.500.500.500
    elif re.match('^(\d{1,3}\.){3}\d{1,3}', resource):
        logger.debug("found IP address %s" % resource)
        r = session.client('ec2').describe_instances(Filters=[
                                    {
                                        'Name': 'private-ip-address',
                                        'Values': [resource]
                                    }
                                ])
        if len(r['Reservations']) == 1:
            return session.resource('ec2').Instance(r['Reservations'][0]['Instances'][0]['InstanceId'])
        elif len(r['Reservations']) < 1:
            # FIXME raise better exception
            raise Exception('No instance found for IP %s' % resource)
        elif len(r['Reservations']) > 1:
            # FIXME raise better exception
            raise Exception('More than 1 instance found for IP %s' % resource)

    else:
        raise NotImplementedError('resource %s not implemented' % resource)


def check_security_group(security_group, resource, inbound=True):
    logger.debug("checking security group %s" % security_group)
    if inbound:
        permissions = security_group.ip_permissions
    else:
        permissions = security_group.ip_permissions_egress

    resource_ip = resource.private_ip_address
    resource_security_groups = resource.security_groups

    # TODO add port and protocol
    matching_rules = [r for r in permissions if check_rule(r, resource)]

    logger.debug("found matching rules: %s" % matching_rules)

    # TODO return matching rules instead
    if len(matching_rules) > 0:
        return True
    else:
        return False


def check_rule(rule, resource):
    # returns true if rule matches resource
    resource_ip = ipaddress.ip_address(resource.private_ip_address)
    resource_security_groups = [sg['GroupId'] for sg in resource.security_groups]

    match = False

    # FIXME this feels a bit crappy
    cidr_blocks = [ipaddress.ip_network(i['CidrIp']) for i in rule['IpRanges']]
    security_groups = [s['GroupId'] for s in rule['UserIdGroupPairs']]

    for cidr_block in cidr_blocks:
        if resource_ip in cidr_block:
            logger.debug("rule %s matches resource IP" % rule)
            return True

    for security_group in security_groups:
        if security_group in resource_security_groups:
            logger.debug("rule %s matches resource sg" % rule)
            return True

    return match


def check_connectivity(resources):
    # does resource_a outbound have rule allowing connectivity to resource_b?
    # does resource_b inbound have rule allowing connectivity from resource_a?

    # FIXME different subnets
    # FIXME different VPC
    # FIXME different accounts

    # errors = []
    checks = {}

    logger.debug("checking connectivity between resources %s" % resources)
    # logger.debug(port)
    # logger.debug(protocol)

    # pre-load security groups
    for n, resource in enumerate(resources):
        logger.debug('resource %s security groups: %s' % (n, resources[0]['resource'].security_groups))
        resources[n]['security_groups'] = [resources[n]['session'].resource('ec2').SecurityGroup(sg['GroupId'])
                                           for sg in resources[n]['resource'].security_groups]

    # find resource A security groups that allow egress to resource B
    checks['sg_egress'] = [sg for sg in resources[0]['security_groups']
                           if check_security_group(sg, resources[1]['resource'], False)]

    # find resource B security groups that allow ingress from resource A
    checks['sg_ingress'] = [sg for sg in resources[1]['security_groups']
                            if check_security_group(sg, resources[0]['resource'], True)]

    # different subnets?

        # different VPC?

            # VPC network ASG

            # VPC peering

        # routing table

    # resource B inbound

    return checks


if __name__ == '__main__':
    # a -> b over port and protocol
    parser = argparse.ArgumentParser(
        description='Check connectivity between 2 AWS resources.',
        # FIXME is there a better way of doing this with formatting?
        epilog="Resource ordering: connectivity is checked from Resource 1 -> Resource 2.\n\n"
               "Examples:\n"
               "=========\n\n"
                # "./can_they_connect.py ops/i-123abc np/10.1.2.3 TCP/8301"
                # "=> can instance i-123abc in ops connect to the instance(*) with IP 10.1.2.3 over TCP/8301?"
               # "./can_they_connect.py i-123abc i-456def\n"
               # "Check which connections can be initiated from instance i-abc123 to instance i-456def\n"
               # "in the same AWS account\n\n"
               # "./can_they_connect.py 123123:i-123abc i-456def\n"
               # "Check which connections can be initiated from instance i-abc123 in the AWS account 123123\n"
               # "to instance i-456def in the inherited shell AWS account (see AWS accounts and credentials below)\n\n"
               # ""
    )
    # TODO document config
    # TODO check by domain, ELB, IP address
    # TODO check ephemeral - but only if TCP/ICMP are protocols maybe????
    # TODO bi-directional flag
    parser.add_argument('resource', nargs=2)
    # TODO check specific ports
    # parser.add_argument('--protocol', default='All', choices=['All', 'TCP', 'UDP'])
    # parser.add_argument('--port', default='0-65535', help='port or port range to check')
    args = parser.parse_args()

    resources = args.resource
    # port = args.port
    # protocol = args.protocol

    for n, resource in enumerate(resources):
        if '/' in resource:
            account = resource.split('/', 1)[0]
            resource_id = resource.split('/', 1)[1]
            session = get_boto_session(account)
        else:
            resource_id = resource
            session = boto3.session.Session()
        # TODO extend for non-instance resources
        resources[n] = {
            'resource': get_resource(resource_id, session),
            'session': session
        }

    checks = check_connectivity(resources)

    pp = pprint.PrettyPrinter(indent=4)
    pp.pprint(checks)
