import httpx
import cloudflare
from cloudflare import Cloudflare
from app import app
from flask import flash


def check_authorization(api_token):
    app.logger.debug(f'API Token: {api_token}')

    if api_token:
        client = Cloudflare(
            api_token=api_token,
        )
    else:
        app.logger.warning('No API token provided')
        flash('No API token provided')

        return False

    api_base = app.config['CLOUDFLARE_API_BASE_URL']

    try:
        response = client.get(api_base + 'user/tokens/verify', cast_to=httpx.Response)

        if response.status_code == 200:
            app.logger.info('Authorization successful')
            accounts_list = client.accounts.list()
            account_id = accounts_list.to_dict()['result'][0]['id']
            account_name = accounts_list.to_dict()['result'][0]['name']
            app.logger.debug(f'Account ID: {account_id}')
            app.logger.debug(f'Account Name: {account_name}')
        else:
            app.logger.warning('Authorization failed')

            return False

    except cloudflare.APIConnectionError as e:
        app.logger.warning("The server could not be reached")
        app.logger.warning(e.__cause__)  # an underlying Exception, likely raised within httpx.
        flash('The server could not be reached')

        return False

    except cloudflare.RateLimitError as e:
        app.logger.warning("A 429 status code was received; we should back off a bit.")
        flash('A 429 status code was received; we should back off a bit.')

        return False

    except cloudflare.APIStatusError as e:
        app.logger.warning("Another non-200-range status code was received")
        app.logger.warning(e.status_code)
        app.logger.warning(e.response)
        flash(f'Another non-200-range status code was received: {e.response}')

        return False

    return client


def api_dns_records_delete(client, zone_id, dns_record_id):
    # messages for showing errors in response template
    messages = []

    try:
        # get DNS record
        dns_record_details = client.dns.records.get(zone_id=zone_id, dns_record_id=dns_record_id)
        app.logger.debug(dns_record_details)
        # delete DNS record
        response = client.dns.records.delete(zone_id=zone_id, dns_record_id=dns_record_id)
        # append response message to messages list
        messages.append({'status': 'SUCCESS', 'message': f'DNS {dns_record_details.type} record "{dns_record_details.name}" was deleted'})
    except Exception as e:
        # get error response
        response = e
        # append response message to messages list
        messages.append({'status': 'ERROR', 'message': e})

    return response, messages


def api_dns_records_edit_proxied(client, zone_id, dns_record_id):
    # messages for showing errors in response template
    messages = []

    try:
        # get DNS record
        dns_record_details = client.dns.records.get(zone_id=zone_id, dns_record_id=dns_record_id)
        app.logger.debug(dns_record_details)
        # edit (update) DNS record proxied
        response = client.dns.records.edit(dns_record_id=dns_record_id, zone_id=zone_id, content=dns_record_details.content, name=dns_record_details.name, type=dns_record_details.type, proxied=True)
        # append response message to messages list
        messages.append({'status': 'SUCCESS', 'message': f'DNS {dns_record_details.type} record "{dns_record_details.name}" proxied status was changed to "True"'})
    except Exception as e:
        # get error response
        response = e
        # append response message to messages list
        messages.append({'status': 'ERROR', 'message': e})

    return response, messages


def api_zones_settings_ipv6_edit(client, zone_id):
    # messages for showing errors in response template
    messages = []

    try:
        # get zone settings
        zone_details = client.zones.get(zone_id=zone_id)
        app.logger.debug(zone_details)
        # edit zone settings IPv6
        response = client.zones.settings.ipv6.edit(zone_id=zone_id, value='on')
        # append response message to messages list
        messages.append({'status': 'SUCCESS', 'message': f'Zone "{zone_details.name}" settings IPv6 was changed to "on"'})
    except Exception as e:
        # get error response
        response = e
        # append response message to messages list
        messages.append({'status': 'ERROR', 'message': e})

    return response, messages


def api_zones_settings_security_level_edit(client, zone_id):
    # messages for showing errors in response template
    messages = []

    try:
        # get zone settings
        zone_details = client.zones.get(zone_id=zone_id)
        app.logger.debug(zone_details)
        # edit zone settings security level
        value = 'essentially_off'
        response = client.zones.settings.security_level.edit(zone_id=zone_id, value=value)
        # append response message to messages list
        messages.append({'status': 'SUCCESS', 'message': f'Zone "{zone_details.name}" settings security level was changed to "{value}"'})
    except Exception as e:
        # get error response
        response = e
        # append response message to messages list
        messages.append({'status': 'ERROR', 'message': e})

    return response, messages