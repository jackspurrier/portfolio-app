# portfolio-app!

ECS781P CLOUD COMPUTING 
Mini Project
Portfolio Analysis


Portfolio Diversification

Portfolio diversification is the practice of spreading your investments around so you’re your exposure for one type of asset is limited (Fidelity). The key to portfolio diversification is balancing comfort and risk against a time horizon. Therefore, investors need to take into consideration the weighting of each investment in a portfolio given a fixed amount of capital. It is important to not ‘put all your eggs in one basket’ and spread risk across different stocks, whilst recognising the risk associated with each stock. Diversification can be across different industries, companies, or even asset classes. For this portfolio, the asset class is fixed as a stock, but the companies can be across many industries. Further, the selection is limited to three stocks. Each stock is represented by a ticker which symbolises the selected company. 
 
The timeseries data is backtested and outputs key performance metrics for a portfolio. Backtesting is the process of seeing how a portfolio would have performed retrospectively. The results are zipped into a dictionary with a backtest key (the following metrics) and the results which are outputted by Empyrial. The metrics are as follows: 
·      Annual Return: the return on the investment expressed as a time weighted annual percentage.
·      Cumulative Return: the aggregate return on the investment given the time period. 
·      Annual Volatility: measure of variance of returns weighted as a annual percentage
·      Winning day ratio: a ratio between the total number of winning trades and losing trades (winners/losers) expressed as a percentage
·      Sharpe ratio: average return earned in excess of the risk-free rate per unit of volatility or total risk
·      Calmar ratio: function of the portfolios average compounded annual rate of return against its maximum drawdown (explained below)
·      Information ratio: measurement of portfolio returns above the returns of a benchmark (e.g. S&P 500) to the volatility of those returns
·      Stability
·      Max Drawdown: the maximum loss from a peak to a trough before a new peak is attained.
·      Sortino ratio: risk adjusted return of an investment asset, portfolio, or strategy. Variation of the Sharpe ratio that differentiates harmful volatility from total overall volatility by using the asset's standard deviation of negative portfolio returns.
·      Skew: the relative number positive returns versus negative returns. A negative skew implies numerous negative returns and few large positive returns. A positive skew implies the opposite.
·      Kurtosis: the degree to which portfolio returns appear in the tails of distribution. A normal distribution has a kurtosis of 3.
·      Tail Ratio
·      Common sense ratio: the tail ratio multiplied by the pain ratio
·      Daily value at risk: calculates the maximum loss expected (or worst case scenario) on an investment, over a given time period and given a specified degree of confidence.
·      Alpha: the excess returns earned on investment above the benchmark return
·      Beta: measure of volatility against the market as a whole.
 
The options for diversification (in terms of weighting) are ‘do not diversify’, ‘medium diversify’, ‘optimise’, and ‘manage risk’. These are the relative weightings for each selected stock. Each selection places a different weighting on each stock according to the appropriate label. Optimise may do so with custom weights based on mean-variance, minimum-variance, global efficient frontier, or hierarchical risk parity (these are all examples of measuring risk). The button is run by importing the Empyrial module.
 
Empyrial Module
Empyrial is a Python-based open-source quantitative investment library for financial institutions and retail investors (https://empyrial.gitbook.io/empyrial/). The library aims to become an all-in-one platform for portfolio management, analysis, and optimisation. Quantstats is another module used in the requirements.txt and Empyrial is mainly a wrapper of financial analysis libraries like Quantstats.
 
Empyrial’s “Engine” is imported to output the KPIs based on a start date, the portfolio tickers, their respective weights and a benchmark (default is SPY). The output is formatted in the same way as in the app. These figures as discussed give good indications about the financial health, risk, and returns of the backtested, diversified portfolio.
 
Passlib Library
Passlib is a python library used for password hashing (https://pypi.org/project/passlib/). In this project, the hash function SHA-256 was implemented to provide security for user passwords stored in the database.
 
Flask WTForms library

Flask WTForms is a python-based library involved in form rendering and validation in web development (https://pypi.org/project/Flask-WTF/). In this project, it was used to render the new user registration form.
 



CRUD Operation:

GET:

When user furnishes 3 stock symbols/ ticker symbols with diversification techniques,( user can also choose  not to diversify the weights of stocks), date specification user receives a response as tabular KPI results (json converted to html ) for the stocks portfolio analysis.

 


Sample external API end point call : 
Sample response







After receiving the data from external API it was processed (normalized, cleaned ) to calculate daily returns, 30 day EWM  for the plots. 

Matplotlib is used to create stock graphs converted to IO bytes and presented as png on the HTML container


Creation of user class for ORM mapping to be done later by sqlalchemy 


POST:











































When user furnishes 3 stock symbols/ ticker symbols with date, diversification techniques ( user can also choose  not to diversify the weights of stocks), date specification a date specification user receives a response whether or not the portfolio details were save successfully .User should use a unique portfolio name as it shouldn’t match with other user’s portfolio details to avoid ambiguity.



PUT:






















Login authentication:

Login manager handler for authenticating user 



Test Cases for role based authentication:

Highest level of access: Pro
testuser123
Testuser123
layem39812@sartess.com

Less restricted level of access:Advanced
testuser12
Testuser12
kikani2144@procowork.com

Most restricted level of access:Basic
testuser1
Testuser1
beweja6058@royins.com
Basic


Sample Tickers:

AAPL
GOOGL
MSFT

Upon selecting tickers clicking on “search portfolio” if user clicks on “get charts” button , user would get daily returns vs smoothened daily returns over a period on 30 days
