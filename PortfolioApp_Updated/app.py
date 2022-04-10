
import datetime
import io
import secrets
from IPython.display import HTML
from click import password_option
import matplotlib.pyplot as plt
from matplotlib.figure import Figure
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
import pandas as pd
import json
import requests
import math
import csv
from empyrial import empyrial, Engine, get_report, get_returns_from_data, get_returns
import numpy as np
import quantstats as qs
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import create_engine, Integer
from flask import Flask, flash, jsonify, redirect, render_template, render_template_string, request, Response, session, \
    flash, url_for
from flask_login import login_user, login_required, current_user, UserMixin, LoginManager
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash
from flask import current_app, Blueprint
from flask_user import roles_required, UserMixin, UserManager
import datetime as dt
from json2html import *



my_portfolio_app = Blueprint('my_portfolio_app', __name__,
                             template_folder='templates')


# Class-based application configuration
class ConfigClass_new(object):
    """ Flask application config """

    # Flask settings
    SECRET_KEY = 'This is an INSECURE secret!! DO NOT use this in production!!'

    # Flask-SQLAlchemy settings
    SQLALCHEMY_DATABASE_URI = 'sqlite:///quickstart_app.sqlite'  # File-based SQL database
    SQLALCHEMY_TRACK_MODIFICATIONS = False  # Avoids SQLAlchemy warning

    # Flask-User settings
    USER_APP_NAME = "Flask-User QuickStart App"  # Shown in and email templates and page footers
    USER_ENABLE_EMAIL = False  # Disable email authentication
    USER_ENABLE_USERNAME = True  # Enable username authentication
    USER_REQUIRE_RETYPE_PASSWORD = False  # Simplify register form

    USER_ENABLE_AUTH0 = False
    # USER_UNAUTHORIZED_ENDPOINT = "login"

    USER_UNAUTHENTICATED_ENDPOINT = "unauthorized_user"


i = 0
j=0

def create_app():
    app = Flask(__name__)
    DIALCT = "mysql"
    DRIVER = "pymysql"
    USERNAME = "root"
    PASSWORD = "199312wmq"
    HOST = "127.0.0.1"
    PORT = "3306"
    DATABASE = "Stock"
    DB_URI = "{}+{}://{}:{}@{}:{}/{}".format(DIALCT, DRIVER, USERNAME, PASSWORD, HOST, PORT, DATABASE)
    app.config['SQLALCHEMY_DATABASE_URI'] = DB_URI
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

    db = SQLAlchemy(app, use_native_unicode='utf-8')
    TEMPLATES_AUTO_RELOAD = True

    """ Flask application factory """

    # Create Flask app load app.config
    app = Flask(__name__)
    app.config.from_object(__name__ + '.ConfigClass_new')

    # Initialize Flask-SQLAlchemy
    db = SQLAlchemy(app)

    db.init_app(app)

    def userid_Default():
        global i
        i += 1
        return i

    class User_Login(db.Model, UserMixin):
        __tablename__ = 'users'
        id = db.Column(db.Integer, primary_key=True, default=userid_Default)
        username = db.Column(db.String(50), nullable=False)
        email = db.Column(db.String(70), nullable=False)
        fullname = db.Column(db.String(50), nullable=False, unique=True)
        password = db.Column(db.String(200), nullable=False)

        roles = db.relationship('RoleNames', secondary='user_roles1')


        def __init__(self, username, email2, password, fullname):
            self.username = username
            self.email = email2
            self.password = generate_password_hash(password)
            self.fullname = fullname

        def __refr__(self):
            return f'<users {self.username}'

        def password_check(self, password):
            return check_password_hash(self.password, password)

        def is_authenticated(self):
            return True

        def is_active(self):
            return True

    class RoleNames(db.Model):
        __tablename__ = 'roles'
        id = db.Column(db.Integer(), primary_key=True)
        name = db.Column(db.String(30))



    class User_Roles(db.Model):
        __tablename__ = 'user_roles1'
        id = db.Column(db.Integer(), primary_key=True)
        user_id = db.Column(db.Integer(), db.ForeignKey('users.id', ondelete='CASCADE'))
        role_id = db.Column(db.Integer(), db.ForeignKey('roles.id', ondelete='CASCADE'))

    def pwd_validator(p):

        if len(p) < 8 and not p.isalnum():
            msg1 = "password must have atleast 8 chars with one capital letter and atleast 1 number"
            return redirect('login1.html', message=msg1)

    def uname_validator(u):

        if len(u) < 4 and not u.isalnum():
            msg1 = "username must have atleast 4 chars and atleast 1 number"
            return redirect('login1.html', message=msg1)

    user_manager_new = UserManager(app, db, User_Login)




    def portfolio_id_Default():
        global j
        j += 1
        return j
    class User_Portfolio_data(db.Model):
        __tablename__ = 'user_portfolio_1'
        id = db.Column(db.Integer,default= portfolio_id_Default)
        userid = db.Column(db.Integer, db.ForeignKey('users.id'))
        ticker_1 = db.Column(db.String(10), nullable=False)
        ticker_2 = db.Column(db.String(10), nullable=False)
        ticker_3 = db.Column(db.String(10), nullable=False)
        diversify = db.Column(db.String(20), nullable=False)
        start_date = db.Column(db.DateTime, nullable=False)
        portfolio_name = db.Column(db.String(30), primary_key=True)
        Annual_return = db.Column(db.String(30), nullable=False)
        Cumulative_return = db.Column(db.String(30), nullable=False)
        Annual_volatility = db.Column(db.String(30), nullable=False)
        Winning_day_ratio = db.Column(db.String(30), nullable=False)
        Sharpe_ratio = db.Column(db.String(30), nullable=False)
        Calmar_ratio = db.Column(db.String(30), nullable=False)
        Information_ratio = db.Column(db.String(30), nullable=False)
        Stability = db.Column(db.String(30), nullable=False)
        Max_Drawdown = db.Column(db.String(30), nullable=False)
        Sortino_ratio = db.Column(db.String(30), nullable=False)
        Skew = db.Column(db.String(30), nullable=False)
        Kurtosis = db.Column(db.String(30), nullable=False)
        Tail_Ratio = db.Column(db.String(30), nullable=False)
        Common_sense_ratio = db.Column(db.String(30), nullable=False)
        Daily_value_at_risk = db.Column(db.String(30), nullable=False)
        Alpha = db.Column(db.String(30), nullable=False)
        Beta = db.Column(db.String(30), nullable=False)







    @app.before_first_request
    def create_table():
        db.create_all()

    loginmgr = LoginManager()

    loginmgr.login_view = 'login'
    loginmgr.init_app(app)

    # user_manager_new.init_app(app, db, User_Login)

    @loginmgr.user_loader
    def load_user(uid):
        try:
            return User_Login.query.filter(User_Login.id == int(uid)).first()
        except:
            return None

    @app.route('/unauthorized_user/')
    def unauthorized_user():
        return ("<h2>Please consider upgrading your access level, contact support@test.com</h2>")

    api_key = "3ZGSDZGITRAO2JWA"
    data_stock = []
    meta_info_stock = []
    df_stock = []
    daily_std_stock = []
    daily_volatility_stock = []
    monthly_volatility_stock = []
    global tickers
    global tk1, tk2, tk3

    def get_ticker_symbol_list():
        match_symbols = []
        with open('nasdaq-listed-symbols_csv.csv', newline='') as csvfile:
            symbol_data = csv.DictReader(csvfile)
            for symbol in symbol_data:
                match_symbols.append(symbol['Symbol'])
        return match_symbols

    def get_daily_stock(stock_sym, api_key='3ZGSDZGITRAO2JWA'):
        url = 'https://www.alphavantage.co/query?function=TIME_SERIES_DAILY&symbol=' + stock_sym + '&apikey=' + api_key
        r = requests.get(url)
        if r.status_code == 200:
            data = r.json()
            return data
        else:
            return jsonify({'error': "Cannot find daily stock values for !" + stock_sym})

    def get_income_statement(stock_sym):
        dict = {}
        json_dict = {}
        url = 'https://www.alphavantage.co/query?function=INCOME_STATEMENT&symbol=' + stock_sym + '&apikey=DLC0NSMS2P7WIW1J'
        r = requests.get(url)

        if r.status_code == 200:
            data = r.json()
            return data
        else:
            return jsonify({'error': "Cannot find daily stock values for !" + stock_sym})

    def get_normalized_json(ticker):
        data = get_daily_stock('IBM', '3ZGSDZGITRAO2JWA')

        stock_dates = data['Time Series (Daily)'].keys()
        stock_open = []
        stock_close = []
        stock_high = []
        stock_low = []

        for dt in stock_dates:
            stock_open.append(data['Time Series (Daily)'][dt]['1. open'])
            stock_close.append(data['Time Series (Daily)'][dt]['4. close'])
            stock_high.append(data['Time Series (Daily)'][dt]['2. high'])
            stock_low.append(data['Time Series (Daily)'][dt]['3. low'])

        df = pd.json_normalize(data, max_level=2)
        df = pd.DataFrame(
            {'Date': stock_dates, 'stock_open': stock_open, 'stock_close': stock_close, 'stock_high': stock_high,
             'stock_low': stock_low})
        df.index = df['Date']
        stock_close_data = df['stock_close'].astype(float)
        stock_open_data = df['stock_open'].astype(float)
        df['returns'] = (stock_close_data - stock_open_data) / stock_open_data * 100
        df['30_EWM'] = df['returns'].ewm(span=30, adjust=False).mean()
        daily_volatility_stock1 = df['returns'].std()
        monthly_volatility_stock1 = daily_volatility_stock1 * math.sqrt(21)

        return df, daily_volatility_stock1, monthly_volatility_stock1

    @app.route('/volatility_plot1.png', methods=['GET', 'POST'])
    def volatility_plot1():
        if "tickers" in session:
            # print(session['tickers'][0], session['tickers'][1],session['tickers'][2])
            tickername = session['tickers']

            fig = create_figure(tickername[0])
            output = io.BytesIO()
            FigureCanvas(fig).print_png(output)
            return Response(output.getvalue(), mimetype='image/png')

    @app.route('/volatility_plot2.png', methods=['GET', 'POST'])
    def volatility_plot2():
        if "tickers" in session:
            tickername = session['tickers']

            fig = create_figure(tickername[1])
            output = io.BytesIO()
            FigureCanvas(fig).print_png(output)
            return Response(output.getvalue(), mimetype='image/png')

    @app.route('/volatility_plot3.png', methods=['GET', 'POST'])
    def volatility_plot3():
        if "tickers" in session:
            tickername = session['tickers']

            fig = create_figure(tickername[2])
            output = io.BytesIO()
            FigureCanvas(fig).print_png(output)
            return Response(output.getvalue(), mimetype='image/png')

    def create_figure(ticker):

        df, daily_volatility_stock1, monthly_volatility_stock1 = get_normalized_json(ticker)

        fig = Figure()
        axis = fig.add_subplot(1, 1, 1)
        axis.plot(df['returns'], color='skyblue', label='Daily Returns')
        axis.plot(df['30_EWM'], color='orange', label='30-Day-EWM')
        axis.set(facecolor="white")
        axis.set_title(ticker, fontsize=20)
        axis.legend(loc=9, fontsize=15)

        return fig

    @app.route('/')
    def index():

        # portfolio = User_Portfolio_data.query.all()
        # portfolio_by_user = User_Portfolio_data.query.all()  # need to add user_id condition after login is implemented
        # return render_template('stock_home.html', tickets=get_ticker_symbol_list(), portfolio=portfolio)
        return render_template('login1.html')

    @app.route('/register/', methods=['GET', 'POST'])
    def register():
        if request.method == 'POST':
            fullname = request.form.get('fullname')
            username = request.form.get('username')
            email1 = request.form.get('email1')
            email2 = request.form.get('email2')
            pwd1 = request.form.get('pwd1')
            pwd2 = request.form.get('pwd2')
            register = request.form.get('register')
            accesslevel = request.form.get('access_level')
            rname = ''

            if User_Login.query.filter_by(username=username).first():
                return render_template('login1.html', message ='User already present')

            if User_Login.query.filter_by(email=email1).first():
                return  render_template('login1.html',message='User already exists with given email')

            if pwd1 != pwd2:
                return render_template('login1.html',message="passwords should match")


            else:
                user = User_Login(username, email1, pwd1, fullname)

                if accesslevel == 'Basic':
                    rname = 'Basic'

                if accesslevel == 'Advanced':
                    rname = 'Advanced'
                if accesslevel == 'Pro':
                    rname = 'Pro'

                user.roles.append(RoleNames(name=accesslevel))

                try:

                    db.session.add(user)
                    db.session.commit()
                    return redirect('/')

                except IntegrityError as e:
                    return render_template('register1.html',message="Invalid email credentials,please try again")



        else:
            return render_template('register1.html')

    @app.route('/reset_pwd/', methods=['GET', 'POST'])
    def reset_pwd():
        useremail = session["user_email"]

        new_pwd1 = request.form.get('pwd1')
        new_pwd2 = request.form.get('pwd2')

        if new_pwd1 != new_pwd2:
            return render_template("reset_pwd.html",message="passwords dont match, please try again! ")
        user = User_Login.query.filter_by(email=useremail).first()
        if user:
            user.password=new_pwd1
            try:

                db.session.commit()
            except SQLAlchemyError as e:
                current_app.logger.error(e)
                return ('<h2>Error while updating user password </h2>')

            return ('<h2>Password updated successfully !!</h2>')


    @app.route('/reset/', methods=['GET', 'POST'])
    def reset():

        reset_email=request.form.get('email')
        session["user_email"] = reset_email
        user=User_Login.query.filter_by(email=reset_email).first()
        if user:
              token= secrets.token_urlsafe(256)
              return render_template("reset_pwd.html", token=token)


        else:
              return("<h2>User does not exist</h2>")

    @app.route('/forgot/', methods=['GET', 'POST'])
    def forgot():
        return render_template('forgotten.html')


    @app.route('/login/', methods=['GET', 'POST'])
    def login():

        username = request.form['username']
        password = request.form['password']

        submit = request.form.get('btnsign')

        if username == '' or password == '':
            msg =  "login failed, username, password fields can't be empty"
            return render_template("login1.html", message=msg)

        if request.method == 'POST':

            uname_validator(username)
            pwd_validator(password)


            user = User_Login.query.filter_by(username=username).first()

            if user:
                if user is not None and user.password_check(password):
                    flash('msg: Successfully logged in')
                    login_user(user)
                    session['uid'] = user.id
                    # portfolio = User_Portfolio_data.query.all()
                    # portfolio_by_user = User_Portfolio_data.query.all()  # need to add user_id condition after login is implemented
                    roleid = User_Roles.query.filter(User_Roles.user_id == user.id).first()
                    role_details = RoleNames.query.with_entities(RoleNames.name).filter_by(id=roleid.id).first()
                    portfolio = User_Portfolio_data.query.filter_by(id=user.id).all()
                    #session["portfolio"] = portfolio
                    session["role"] = role_details[0]
                    session["username"] = current_user.username
                    return render_template('stock_home.html', tickets=get_ticker_symbol_list(), portfolio=portfolio,
                                           name=current_user.username, role=role_details[0])
            else:
                msg = "invalid credentials, please use valid username and password!!"
                return render_template("login1.html", message=msg)
        else:
            flash("invalid credentials, please use valid username and password!!")
            return render_template("login1.html")

        flash("invalid credentials, please use valid username and password!!")
        return render_template("login1.html")

    @app.route('/portfolio/', methods=['post'])
    def post():
        global start_date
        global api_key
        global portfolio
        user_id = int(session["uid"])
        tk1 = request.form.get('ticket1')
        tk2 = request.form.get('ticket2')
        tk3 = request.form.get('ticket3')
        diversify = request.form.get('portfolio')
        start_date = request.form.get('date')
        portfolio_name = request.form.get('portfolio_name')

        # Getting portfolio names of currently logged in user
        get_portfolio_name = request.form.get('saved_portfolio_names')

        daily_freq = request.form.get('volatility_radio_sub1')
        monthly_freq = request.form.get('volatility_radio_sub2')

        # RETRIVING PARAMETERS FROM FORM FOR PERFORMING PUT OPERATION
        diversification_method = request.form.get('diversification_method')
        update_portfolio_name = request.form.get('update_portfolio_names')
        update_date = request.form.get('update_date')

        delete_portfolio_name = request.form.get('delete_portfolio_names')

        freq = ''

        if daily_freq == '':
            freq = monthly_freq
        else:
            freq = daily_freq

        tickers = [tk1, tk2, tk3]
        if tk1 != tk2 and tk2 != tk3 and tk1 != tk3:
            tickers_selected = [tk1, tk2, tk3]
            session['tickers'] = tickers_selected
            if diversify == 'Do not diversify':
                tickers_portfolio = Engine(start_date=start_date, portfolio=tickers, weights=[0.3, 0.3, 0.3],
                                           benchmark=["SPY"], rebalance='1y')
                get_report(tickers_portfolio)

            elif diversify == "Medium diversify":
                tickers_portfolio = Engine(start_date=start_date, portfolio=tickers, optimizer="MINVAR",
                                           diversification=1.3)
                get_report(tickers_portfolio)
            elif diversify == 'Optimize':
                tickers_portfolio = Engine(start_date=start_date, portfolio=tickers, benchmark=["SPY"], optimizer="EF")

                get_report(tickers_portfolio)
            else:
                tickers_portfolio = Engine(start_date=start_date, portfolio=tickers,
                                           risk_manager={"Max Dropdown : -0.25"})

                get_report(tickers_portfolio)

            dict_new = eval(json.dumps(empyrial.df))
            data_key = dict_new['']
            data_value = dict_new['Backtest']
            Backtest = dict(zip(data_key, data_value))

        elif request.form.get('get_my_portfolios') == 'get_my_portfolios':
            if get_portfolio_name != '':
                return redirect(url_for('get_my_portfolios', my_portfolio_name=get_portfolio_name))
            else:
                return jsonify({'Error': 'Please select a valid portfolio name '})

        if request.form.get('update_portfolio') == 'Update Portfolio':
            if diversification_method != '--Please Select--' and update_portfolio_name != '--Please Select--':
                return redirect(url_for('change_diversification', portfolio_name=update_portfolio_name,
                                        diversify=diversification_method, update_date=update_date))
            else:
                return jsonify({'Error':'Please select both portfolio name and diversification technique to update'})

        if request.form.get('delete_portfolio') == 'Delete Portfolio':
            if delete_portfolio_name != '--Please Select--':
                return redirect(url_for('delete', portfolio_name=delete_portfolio_name))
            else:
                return jsonify ({'Error' : 'Please select both portfolio name and diversification technique to update'})

        if start_date is not None:
            dt_date = dt.datetime.strptime(start_date, "%Y-%m-%d")
        if request.form.get('Save portfolio') == 'Save portfolio':

            if User_Portfolio_data.query.filter_by(portfolio_name=portfolio_name).first():
                return jsonify({'Error':'Portfolio already exists'})


            portfolio = User_Portfolio_data( ticker_1=tk1,
                                            ticker_2=tk2, ticker_3=tk3, diversify=diversify, start_date=dt_date,
                                            portfolio_name=portfolio_name,
                                            Annual_return=Backtest['Annual return'],
                                            Cumulative_return=Backtest['Cumulative return'],
                                            Annual_volatility=Backtest['Annual volatility'],
                                            Winning_day_ratio=Backtest['Winning day ratio'],
                                            Sharpe_ratio=Backtest['Sharpe ratio'],
                                            Calmar_ratio=Backtest['Calmar ratio'],
                                            Information_ratio=Backtest['Information ratio'],
                                            Stability=Backtest['Stability'], Max_Drawdown=Backtest['Max Drawdown'],
                                            Sortino_ratio=Backtest['Sortino ratio'],
                                            Skew=Backtest['Skew'], Kurtosis=Backtest['Kurtosis'],
                                            Tail_Ratio=Backtest['Tail Ratio'],
                                            Common_sense_ratio=Backtest['Common sense ratio'],
                                            Daily_value_at_risk=Backtest['Daily value at risk'],
                                            Alpha=Backtest['Alpha'], Beta=Backtest['Beta'])
            try:
                db.session.add(portfolio)
                db.session.commit()
            except SQLAlchemyError as e:
                current_app.logger.error(e)
                return e

            return jsonify('Message: {} saved successfully'.format(portfolio_name))



        elif request.form.get('search details') == 'search details':

            dict_new = eval(json.dumps(empyrial.df))
            data_key = dict_new['']
            data_value = dict_new['Backtest']
            Backtest = dict(zip(data_key, data_value))

            ticker_1 = tk1
            ticker_2 = tk2
            ticker_3 = tk3
            Diversify = diversify
            Start_Date = start_date
            Annual_return = Backtest['Annual return']
            Cumulative_return = Backtest['Cumulative return']
            Annual_volatility = Backtest['Annual volatility']
            Winning_day_ratio = Backtest['Winning day ratio']
            Sharpe_ratio = Backtest['Sharpe ratio']
            Calmar_ratio = Backtest['Calmar ratio']
            Information_ratio = Backtest['Information ratio']
            Stability = Backtest['Stability']
            Max_Drawdown = Backtest['Max Drawdown']
            Sortino_ratio = Backtest['Sortino ratio']
            Skew = Backtest['Skew']
            Kurtosis = Backtest['Kurtosis']
            Tail_Ratio = Backtest['Tail Ratio']
            Common_sense_ratio = Backtest['Common sense ratio']
            Daily_value_at_risk = Backtest['Daily value at risk']
            Alpha = Backtest['Alpha']
            Beta = Backtest['Beta']

            dt_start = dt.datetime.strptime(start_date, "%Y-%m-%d")
            dict_get = {'Ticker1 ': ticker_1,
                        'Ticker2 ': ticker_2,
                        'Ticker3 ': ticker_3,
                        'Diversification_Method': Diversify,
                        'Start_Date': start_date,
                        'Annual_return': Annual_return,
                        'Cumulative_return': Cumulative_return,
                        'Annual_volatility': Annual_volatility,
                        'Winning_day_ratio': Winning_day_ratio,
                        'Sharpe_ratio': Sharpe_ratio,
                        'Calmar_ratio': Calmar_ratio,
                        'Information_ratio': Information_ratio,
                        'Stability': Stability,
                        'Max_Drawdown': Max_Drawdown,
                        'Sortino_ratio': Sortino_ratio,
                        'Skew': Skew,
                        'Kurtosis': Kurtosis,
                        'Tail_Ratio': Tail_Ratio,
                        'Common_sense_ratio': Common_sense_ratio,
                        'Daily_value_at_risk': Daily_value_at_risk,
                        'Alpha': Alpha,
                        'Beta': Beta
                        }

            get_portflio_data_json = json.dumps(dict_get)

            get_portfolio_data_html = json2html.convert(json=get_portflio_data_json)
            return get_portfolio_data_html


        else:
            return jsonify({'Error':'Please select three different tickers'})

    @app.route('/all_portfolio/', methods=['get'])
    def get():
        portfolio = User_Portfolio_data.query.all()
        if len(portfolio) == 0:

            return ('<h2>Error: No existing portfolio at this moment</h2>')

        else:

            return render_template('all_portfolio.html', portfolio=portfolio)

    @app.route('/my_portfolios/<my_portfolio_name>', methods=['get'])
    def get_my_portfolios(my_portfolio_name):
        uid = int(session["uid"])
        datasets = User_Portfolio_data.query.filter_by(portfolio_name=my_portfolio_name, id=uid).first()
        if datasets != None:

            Ticker1 = datasets.ticker_1
            Ticker2 = datasets.ticker_2
            Ticker3 = datasets.ticker_3
            Diversify = datasets.diversify
            Start_Date = dt.datetime.strftime(datasets.start_date, "%Y-%m-%d")
            Annual_return = datasets.Annual_return
            Cumulative_return = datasets.Cumulative_return
            Annual_volatility = datasets.Annual_volatility
            Winning_day_ratio = datasets.Winning_day_ratio
            Sharpe_ratio = datasets.Sharpe_ratio
            Calmar_ratio = datasets.Calmar_ratio
            Information_ratio = datasets.Information_ratio
            Stability = datasets.Stability
            Max_Drawdown = datasets.Max_Drawdown
            Sortino_ratio = datasets.Sortino_ratio
            Skew = datasets.Skew
            Kurtosis = datasets.Kurtosis
            Tail_Ratio = datasets.Tail_Ratio
            Common_sense_ratio = datasets.Common_sense_ratio
            Daily_value_at_risk = datasets.Daily_value_at_risk
            Alpha = datasets.Alpha
            Beta = datasets.Beta

            dict = {'Ticker1 ': Ticker1,
                    'Ticker2 ': Ticker2,
                    'Ticker3 ': Ticker3,
                    'Start_Date': Start_Date,
                    'Diversification_Method': Diversify,
                    'Annual_return': Annual_return,
                    'Cumulative_return': Cumulative_return,
                    'Annual_volatility': Annual_volatility,
                    'Winning_day_ratio': Winning_day_ratio,
                    'Sharpe_ratio': Sharpe_ratio,
                    'Calmar_ratio': Calmar_ratio,
                    'Information_ratio': Information_ratio,
                    'Stability': Stability,
                    'Max_Drawdown': Max_Drawdown,
                    'Sortino_ratio': Sortino_ratio,
                    'Skew': Skew,
                    'Kurtosis': Kurtosis,
                    'Tail_Ratio': Tail_Ratio,
                    'Common_sense_ratio': Common_sense_ratio,
                    'Daily_value_at_risk': Daily_value_at_risk,
                    'Alpha': Alpha,
                    'Beta': Beta
                    }

            user_portflio_data_json = json.dumps(dict)
            user_portfolio_data_html = json2html.convert(json=user_portflio_data_json)
            return user_portfolio_data_html
        else:
            return jsonify('Error : No existing portfolio with name {} at this moment'.format(my_portfolio_name))


    @app.route('/all_portfolio/<portfolio_name>/', methods=['delete', 'get'])
    @roles_required('Pro')
    def delete(portfolio_name):
        uid = int(session["uid"])
        datasets = User_Portfolio_data.query.filter_by(portfolio_name=portfolio_name, userid=uid).delete()
        if datasets != None:
            try:
                db.session.commit()
            except SQLAlchemyError as e:
                current_app.logger.error(e)
                return jsonify("Error while updating user database : {}".format(e.message))
            return jsonify('Error: Message : {} deleted successfully!!'.format(portfolio_name))


        else:
            return jsonify ({'Error':'<h2>No Records Found</h2>'})

    @app.route('/portfolio/<portfolio_name>/<diversify>/<update_date>/', methods=['put', 'get'])
    @roles_required(['Advanced','Pro'])
    def change_diversification(portfolio_name, diversify, update_date):

        if current_user.is_authenticated:
            uid = int(session["uid"])
            datasets = User_Portfolio_data.query.filter_by(portfolio_name=portfolio_name, userid=uid).first()

            if datasets != None:

                start_date_formatted = update_date
                if diversify == 'Do not diversify':
                    tickers_portfolio = Engine(start_date=start_date_formatted,
                                               portfolio=[datasets.ticker_1, datasets.ticker_2, datasets.ticker_3],
                                               weights=[0.3, 0.3, 0.3],
                                               benchmark=["SPY"],
                                               rebalance='1y')
                    get_report(tickers_portfolio)

                elif diversify == "Medium diversify":
                    tickers_portfolio = Engine(start_date=start_date_formatted,
                                               portfolio=[datasets.ticker_1, datasets.ticker_2, datasets.ticker_3],
                                               optimizer="MINVAR", diversification=1.3)
                    get_report(tickers_portfolio)
                elif diversify == 'Optimize':
                    tickers_portfolio = Engine(start_date=start_date_formatted,
                                               portfolio=[datasets.ticker_1, datasets.ticker_2, datasets.ticker_3],
                                               benchmark=["SPY"], optimizer="EF")
                    get_report(tickers_portfolio)
                else:
                    tickers_portfolio = Engine(start_date=start_date_formatted,
                                               portfolio=[datasets.ticker_1, datasets.ticker_2, datasets.ticker_3],
                                               risk_manager={"Max Dropdown : -0.25"})
                    get_report(tickers_portfolio)
                udate_dt = dt.datetime.strptime(update_date, "%Y-%m-%d")
                dict_new = eval(json.dumps(empyrial.df))
                data_key = dict_new['']
                data_value = dict_new['Backtest']
                Backtest = dict(zip(data_key, data_value))

                datasets.start_date = udate_dt.date()
                datasets.diversify = diversify
                datasets.Annual_return = Backtest['Annual return']
                datasets.Cumulative_return = Backtest['Cumulative return']
                datasets.Annual_volatility = Backtest['Annual volatility']
                datasets.Winning_day_ratio = Backtest['Winning day ratio']
                datasets.Sharpe_ratio = Backtest['Sharpe ratio']
                datasets.Calmar_ratio = Backtest['Calmar ratio']
                datasets.Information_ratio = Backtest['Information ratio']
                datasets.Stability = Backtest['Stability']
                datasets.Max_Drawdown = Backtest['Max Drawdown']
                datasets.Sortino_ratio = Backtest['Sortino ratio']
                datasets.Skew = Backtest['Skew']
                datasets.Kurtosis = Backtest['Kurtosis']
                datasets.Tail_Ratio = Backtest['Tail Ratio']
                datasets.Common_sense_ratio = Backtest['Common sense ratio']
                datasets.Daily_value_at_risk = Backtest['Daily value at risk']
                datasets.Alpha = Backtest['Alpha']
                datasets.Beta = Backtest['Beta']

            # need to add po
            try:

                db.session.commit()
            except SQLAlchemyError as e:
                current_app.logger.error(e)
                return jsonify({'Error': 'Error while updating user database'})
            return jsonify('Message: {} updated successfully!!'.format(portfolio_name))



        else:
            return jsonify({'Message': '<h1>not authorized</h1>'})

    return app


if __name__ == "__main__":
    app = create_app()

    app.run(debug=True)
