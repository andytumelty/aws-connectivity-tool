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
#logger.setLevel(logging.DEBUG)

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
    logger.debug("finding resource type for %s" % resource)
    if resource.split('-', 1)[0] == 'i':
        logger.debug("got resource type instance %s" % resource)
        instances = session.client('ec2').describe_instances(Filters=[{'Name': 'instance-id', 'Values': [resource]}])
        if len(instances['Reservations']) == 1:
            return {'type': 'instance', 'data': instances['Reservations'][0]['Instances'][0]}
        else:
            raise Exception("Couldn't find instance %s" % resource)

    # IP address, for now assume EC2 instance
    # FIXME this will match on external IPs, and non-valid ones like 500.500.500.500
    elif re.match('^(\d{1,3}\.){3}\d{1,3}', resource):
        logger.debug("got resource type IP address %s" % resource)
        instances = session.client('ec2').describe_instances(Filters=[{'Name': 'private-ip-address', 'Values': [resource]}])
        if len(instances['Reservations']) == 1:
            logger.debug('found instance %s with IP address %s' % (instances['Reservations'][0]['Instances'][0]['InstanceId'], resource))
            return {'type': 'instance', 'data': instances['Reservations'][0]['Instances'][0] }
        elif len(instances['Reservations']) < 1:
            logger.debug('no instance found for IP address %s, assuming external' % resource)
            return {'type': 'ip_address', 'data': {'ip_address': resource}}
        elif len(instances['Reservations']) > 1:
            # FIXME raise better exception
            raise Exception('More than 1 instance found for IP %s' % resource)

    # c = boto3.client('elb')
    # elbs = c.describe_load_balancers(LoadBalancerNames=['elb-outboundproxy-dcbc-prd1'])
    # or DNS name
    # if len(elbs['LoadBalancerDescriptions']) == 1
    # elbs['LoadBalancerDescriptions'][0]['SecurityGroups'] -> ['sg-f0ae0289']
    else:
        raise NotImplementedError('resource %s not implemented' % resource)


def check_security_group(security_group, resource, inbound=True):
    logger.debug("checking security group %s" % security_group)
    if inbound:
        permissions = security_group.ip_permissions
    else:
        permissions = security_group.ip_permissions_egress

    # TODO add port and protocol
    matching_rules = [r for r in permissions if check_rule(r, resource)]

    logger.debug("found matching rules: %s" % matching_rules)
    return matching_rules


def check_rule(rule, resource):
    resource_security_groups = []
    resource_ip = ''

    # returns true if rule matches resource
    if resource['type'] == 'instance':
        resource_ip = ipaddress.ip_address(resource['data']['PrivateIpAddress'])
        resource_security_groups = [sg['GroupId'] for sg in resource['data']['SecurityGroups']]
    if resource['type'] == 'ip_address':
        resource_ip = ipaddress.ip_address(resource['data']['ip_address'])

    match = False

    # FIXME this feels a bit crappy
    cidr_blocks = [ipaddress.ip_network(i['CidrIp']) for i in rule['IpRanges']]
    security_groups = [s['GroupId'] for s in rule['UserIdGroupPairs']]

    if resource_ip != '':
        for cidr_block in cidr_blocks:
            if resource_ip in cidr_block:
                logger.debug("rule %s matches resource IP" % rule)
                return True

    if resource_security_groups != []:
        for security_group in security_groups:
            if security_group in resource_security_groups:
                logger.debug("rule %s matches resource sg" % rule)
                return True

    return match


def check_connectivity(resources):
    logger.debug('checking connectivity between %s and %s' % (resources[0]['id'], resources[1]['id']))

    checks = {}

    logger.debug('checking egress from %s to %s' % (resources[0]['id'], resources[1]['id']))
    # FIXME refactor
    if resources[0]['resource']['type'] in ['instance']:
        # find resource A security groups that allow egress to resource B
        matching_sg = []
        for sg in resources[0]['resource']['data']['SecurityGroups']:
            sg_resource = resources[0]['session'].resource('ec2').SecurityGroup(sg['GroupId'])
            matching_rules = check_security_group(sg_resource, resources[1]['resource'], False)
            if matching_rules:
                # matching_sg.append(security_group_to_dict(sg_resource, False))
                matching_sg.append({'sg_id': sg_resource.id, 'matching_rules': matching_rules})

        result = len(matching_sg) > 0
        reason = '%s matching security groups found' % len(matching_sg)

        checks['sg_egress'] = {'result': result, 'reason': reason, 'data': matching_sg}
    else:
        checks['sg_egress'] = {'result': True, 'reason': 'not applicable', 'data': []}

    logger.debug('checking ingress from %s to %s' % (resources[0]['id'], resources[1]['id']))
    if resources[1]['resource']['type'] in ['instance']:
        matching_sg = []
        for sg in resources[1]['resource']['data']['SecurityGroups']:
            sg_resource = resources[1]['session'].resource('ec2').SecurityGroup(sg['GroupId'])
            matching_rules = check_security_group(sg_resource, resources[1]['resource'], True)
            if matching_rules:
                # matching_sg.append(security_group_to_dict(sg_resource, False))
                matching_sg.append({'sg_id': sg_resource.id, 'matching_rules': matching_rules})

        result = len(matching_sg) > 0
        reason = '%s matching security groups found' % len(matching_sg)

        checks['sg_ingress'] = {'result': result, 'reason': reason, 'data': matching_sg}
    else:
        checks['sg_egress'] = {'result': True, 'reason': 'not applicable', 'data': []}

    # if [resources[0]['resource'].subnet_id != resources[0]['resource'].subnet_id]:
    #     logger.debug('resources not in same subnet, checking routing')

        # if [resources[0]['resource'].vpc_id != resources[0]['resource'].vpc_id]:
        #     logger.debug('resources not in same subnet, checking peering connection')
    # different subnets?

        # different VPC?

            # VPC network ASG

            # VPC peering

        # routing table

    # resource B inbound

    return checks


# This should really be an encoder, but I'm also convinced I'm not the first person to want to do that.
# For now, extracting the fields I want is good enough.
def security_group_to_dict(sg, ingress=True):
    if ingress:
        perms = sg.ip_permissions
    else:
        perms = sg.ip_permissions_egress
    return {
        'id': sg.id,
        'group_name': sg.group_name,
        'rules': perms,
        'vpc_id': sg.vpc_id
        #'tags': sg.tags
    }


def print_checks(checks):
    # Desired Output
    #
    # Security Group Egress: Allowed
    #   └─ sg-123abc
    #      └─ 10.1.0.0/16 All
    #   └─ sg-123abc
    #      └─ 0.0.0.0/0 All
    #   └─ sg-123abc
    #      └─ 0.0.0.0/0 All
    # Security Group Ingress: Allowed
    #   └─ sg-123ab22c
    #      └─ 10.0.0.0/8 8301/TCP
    #   └─ sg-123abc
    #      └─ sg-abc123 -1
    # TODO refactor ingress and egress
    if 'sg_egress' in checks.keys():
        if checks['sg_egress']['result']:
            result = 'Allowed'
        else:
            result = 'Blocked'
        result = '%s (%s)' % (result, checks['sg_egress']['reason'])
        print('Security Group Egress: %s' % result)
        for match in checks['sg_egress']['data']:
            print('  └─ %s' % match['sg_id'])
            for rule in match['matching_rules']:
                groups = [g['GroupId'] for g in rule['UserIdGroupPairs']]
                ipranges = [c['CidrIp'] for c in rule['IpRanges']]
                allowed = groups + ipranges
                # TODO print port and protocol
                print('     └─ %s' % ','.join(allowed))


    if 'sg_ingress' in checks.keys():
        if checks['sg_ingress']['result']:
            result = 'Allowed'
        else:
            result = 'Blocked'
        result = '%s (%s)' % (result, checks['sg_ingress']['reason'])
        print('Security Group Ingress: %s' % result)
        for match in checks['sg_ingress']['data']:
            print('  └─ %s' % match['sg_id'])
            for rule in match['matching_rules']:
                groups = [g['GroupId'] for g in rule['UserIdGroupPairs']]
                ipranges = [c['CidrIp'] for c in rule['IpRanges']]
                allowed = groups + ipranges
                # TODO print port and protocol
                print('     └─ %s' % ','.join(allowed))


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
    parser.add_argument('resource1', nargs=1, metavar='resource')
    parser.add_argument('resource2', nargs='+', metavar='resource')
    args = parser.parse_args()

    resources = args.resource1 + args.resource2

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
            'id': resource_id,
            'resource': get_resource(resource_id, session),
            'session': session
        }

    while len(resources) > 1:
        checks = check_connectivity(resources[:2])
        #pp = pprint.PrettyPrinter(indent=4)
        #pp.pprint(checks)

        print_checks(checks)
        resources = resources[1:]
