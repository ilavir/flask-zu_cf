from flask import render_template, flash, redirect, url_for, session
from app import app
from app.forms import LoginForm, ApiTokenForm


@app.route('/')
@app.route('/index')
def index():

    user = {'username': 'Miguel'}

    if session.get('api_token'):
        app.logger.debug(f'api_token: {session['api_token']}')
        cf_api_token = session['api_token']
    else:
        cf_api_token = None

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

    if session.get('api_token'):
        app.logger.debug(f'api_token: {session['api_token']}')
        cf_api_token = session['api_token']
    else:
        cf_api_token = None

    return render_template('api_token.html', title='API Token', form=form, api_token=cf_api_token)
