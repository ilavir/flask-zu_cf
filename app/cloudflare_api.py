import os
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
            # print(response.json())
            # print(client.accounts.list().to_json())
            accounts_list = client.accounts.list()
            account_id = accounts_list.to_dict()['result'][0]['id']
            account_name = accounts_list.to_dict()['result'][0]['name']
            app.logger.info(f'Account ID: {account_id}')
            app.logger.info(f'Account Name: {account_name}')
            flash(f'Account ID: {account_id}')
            flash(f'Account Name: {account_name}')
        else:
            print('Authorization failed')

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
