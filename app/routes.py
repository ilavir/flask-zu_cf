import pprint
from flask import render_template, flash, redirect, url_for, session, request
from flask_login import current_user, login_user, logout_user, login_required
from app import app
from app.models import User
from app.forms import LoginForm, ApiTokenForm, Ipv4ToIpv6Form
from app.cloudflare_api import check_authorization
from app.models import User

users = {'test': {'password': 'test'}}


@app.route('/')
@app.route('/index')
@login_required
def index():
    form = Ipv4ToIpv6Form()

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

            cloudflare_info['zones'].append(
                {
                    'id': zone_id,
                    'name': zone_name,
                    'security_level': zone_security_level,
                    'dns': []
                }
            )

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

    else:
        flash('Authorization failed. Please, check Cloudflare API Token.')

        cloudflare_info = {
            'api_token': cf_api_token,
        }

    return render_template('index.html', title='Dashboard', cf=cloudflare_info, form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('api_token'))

    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        if username in users and users[username]['password'] == form.password.data:
            user = User()
            user.id = username
            login_user(user, remember=form.remember_me.data)

            return redirect(url_for('api_token'))
        else:
            flash('Invalid username or password')
            return redirect(url_for('login'))

    return render_template('login.html', title='Sign In', form=form)


@app.route('/logout')
def logout():
    session.pop('api_token', None)
    session.pop('account_id', None)
    session.pop('account_name', None)
    logout_user()
    return redirect(url_for('login'))


@app.route('/api_token', methods=['GET', 'POST'])
@login_required
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
            account_id = client.accounts.list().to_dict()['result'][0]['id']
            account_name = client.accounts.list().to_dict()['result'][0]['name']
            session['account_id'] = account_id
            session['account_name'] = account_name
            print(f'Account ID: {account_id}, {account_name}')
            # session['client'] = client
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
    client = check_authorization(session.get('api_token'))

    if client:
        try:
            response = client.zones.settings.security_level.edit(zone_id=zone_id, value='essentially_off')
            print(response)
            message = {'status': 'SUCCESS!', 'message': 'Zone security level was changed to "essentially_off"'}
        except Exception as e:
            message = {'status': 'ERROR!', 'message': e}
        finally:
            return render_template('response.html', message=message)
    else:
        flash('Authorization failed. Please, check Cloudflare API Token.')
        return redirect(url_for('api_token'))


@app.route('/_change_dns_proxied/<dns_record_id>')
def change_dns_proxied(dns_record_id):
    zone_id = request.args.get('zone_id')
    content = request.args.get('content')
    name = request.args.get('name')
    type = request.args.get('type')

    client = check_authorization(session.get('api_token'))

    if client:
        try:
            response = client.dns.records.update(dns_record_id=dns_record_id, zone_id=zone_id, content=content, name=name, type=type, proxied=True)
            print(response)
            message = {'status': 'SUCCESS!', 'message': f'DNS record {type} "{name}" Proxied status was changed to "True"'}
        except Exception as e:
            print(e)
            message = {'status': 'ERROR!', 'message': e}
        finally:
            return render_template('response.html', message=message)
    else:
        flash('Authorization failed. Please, check Cloudflare API Token.')
        return redirect(url_for('api_token'))


@app.route('/_copy_dns_a_to_aaaa', methods=['POST'])
def copy_dns_a_to_aaaa():
    form = Ipv4ToIpv6Form()

    if form.validate_on_submit():
        zone_id = request.form.get('zone_id')
        ipv6_address = request.form.get('ipv6_address')
        print(zone_id, ipv6_address)

        client = check_authorization(session.get('api_token'))
        if client:
            try:
                zone_dns_records_list = client.dns.records.list(zone_id=zone_id).to_dict()

                for dns_record in zone_dns_records_list['result']:
                    if dns_record['type'] == 'A':
                        client.dns.records.create(zone_id=zone_id, content=ipv6_address, name=dns_record['name'], type='AAAA', proxied=True)

                message = {'status': 'SUCCESS!', 'message': f'IPv4 to IPv6 was copied successfully'}
            except Exception as e:
                print(e)
                message = {'status': 'ERROR!', 'message': e}
            finally:
                return render_template('response.html', message=message)

        else:
            flash('Authorization failed. Please, check Cloudflare API Token.')
            return redirect(url_for('api_token'))

    else:
        flash('Form data is invalid. Please, check form data.')
        return redirect(url_for('index'))


@app.route('/_dns_record_delete')
def dns_record_delete():
    zone_id = request.args.get('zone_id')
    dns_record_id = request.args.get('dns_record_id')
    name = request.args.get('name')
    type = request.args.get('type')

    client = check_authorization(session.get('api_token'))

    if client:
        try:
            response = client.dns.records.delete(zone_id=zone_id, dns_record_id=dns_record_id)
            print(response)
            message = {'status': 'SUCCESS!', 'message': f'DNS record {type} "{name}" was deleted'}
        except Exception as e:
            print(e)
            message = {'status': 'ERROR!', 'message': e}
        finally:
            return render_template('response.html', message=message)
    else:
        flash('Authorization failed. Please, check Cloudflare API Token.')
        return redirect(url_for('api_token'))
