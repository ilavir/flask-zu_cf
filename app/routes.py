import pprint
from flask import render_template, flash, redirect, url_for, session, request
from app import app
from app.forms import LoginForm, ApiTokenForm
from app.cloudflare_api import check_authorization


@app.route('/')
@app.route('/index')
def index():
    user = {'username': 'Miguel'}

    app.logger.debug(f'api_token: {session.get('api_token')}')
    client = check_authorization(session.get('api_token'))
    app.logger.debug(f'client: {client}')
    cf_api_token = session.get('api_token')

    if client:
        cloudflare_info = {
            'api_token': cf_api_token,
            'zones': []
        }

        zones_list = client.zones.list().to_dict()
        cloudflare_info['zones_count'] = zones_list['result_info']['total_count']

        for zone in zones_list['result']:
            zone_id = zone['id']
            zone_name = zone['name']
            zone_security_level = client.zones.settings.security_level.get(zone_id=zone_id).to_dict().get('value')
            print(zone_security_level)

            cloudflare_info['zones'].append(
                {
                    'id': zone_id,
                    'name': zone_name,
                    'security_level': zone_security_level,
                    'dns': []
                }
            )

            pprint.pprint(client.dns.records.list(zone_id=zone_id).to_dict())
            zone_dns_records_list = client.dns.records.list(zone_id=zone_id).to_dict()
            cloudflare_info['zones'][-1]['dns_count'] = zone_dns_records_list['result_info']['total_count']

            for dns_record in zone_dns_records_list['result']:
                cloudflare_info['zones'][-1]['dns'].append(
                    {
                        'id': dns_record['id'],
                        'name': dns_record['name'],
                        'type': dns_record['type'],
                        'content': dns_record['content'],
                        # 'proxiable': dns_record['proxiable'],
                        'proxied': dns_record['proxied'],
                    }
                )

        pprint.pprint(zones_list)
        pprint.pprint(cloudflare_info)

    else:
        flash('Authorization failed. Please, check Cloudflare API Token.')

        cloudflare_info = {
            'api_token': cf_api_token,
        }

    return render_template('index.html', title='Home', user=user, cf=cloudflare_info)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        flash('Login requested for user {}, remember_me={}'.format(
            form.username.data, form.remember_me.data))

        return redirect(url_for('index'))

    return render_template('login.html', title='Sign In', form=form)


@app.route('/api_token', methods=['GET', 'POST'])
def api_token():
    form = ApiTokenForm()

    if form.validate_on_submit():
        session['api_token'] = form.api_token.data
        app.logger.debug(f'api_token: {session['api_token']}')
        flash('API Token saved: {}'.format(form.api_token.data))
    # else:
    #     flash('Session expired. Please, try again or refresh page.')
    #     redirect(url_for('api_token'))

    app.logger.debug(f'api_token: {session.get('api_token')}')
    client = check_authorization(session.get('api_token'))
    app.logger.debug(f'client: {client}')

    if client:
        # session['client'] = client
        pass
    else:
        flash('Authorization failed. Please, check Cloudflare API Token.')

    if session.get('api_token') and session.get('api_token') is not None:
        app.logger.debug(f'api_token: {session['api_token']}')
        cf_api_token = session['api_token']
    else:
        cf_api_token = None

    return render_template('api_token.html', title='API Token', form=form, api_token=cf_api_token)


@app.route('/_change_zone_security_level/<zone_id>')
def change_zone_security_level(zone_id):
    # zone_id = request.args.get('zone_id')
    return zone_id


@app.route('/_change_dns_proxied')
def change_dns_proxied():
    return 'OK'
