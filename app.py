import os
import locale
locale.setlocale(locale.LC_ALL, '')
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

#webpage home
@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    rows = db.execute("SELECT * FROM people_stocks WHERE username_id = (?)", session["user_id"])
    total_stock_value = 0.00
    for row in rows:
        #delete rows where shares = 0
        if int(row["stock_number"]) == 0:
            db.execute("DELETE FROM people_stocks WHERE stock_name=(?)", row["stock_name"])
        #update the user's total stock value
        temporary = row["total_cost"]
        temporary = temporary.replace(',', '')
        temporary = temporary.replace('$', '')
        total_stock_value = total_stock_value + float(temporary)
        #update the stock prices
        new_stock_price = lookup(row["stock_name"])["price"]
        db.execute("UPDATE people_stocks SET stock_price = (?) WHERE username_id = (?) AND stock_name = (?)", new_stock_price, session["user_id"], row["stock_name"])

    user_information = db.execute("SELECT * FROM users WHERE id = (?)", session["user_id"])
    cash = user_information[0]["cash"]
    cash=cash.replace("$","")
    cash=cash.replace(",","")
    cash = float(cash)
    rows = db.execute("SELECT * FROM people_stocks WHERE username_id = (?)", session["user_id"])
    return render_template("index.html", total_stock_value = usd(total_stock_value), cash = usd(cash), rows = rows)




@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        user_information = db.execute("SELECT * FROM users WHERE id = (?)", session["user_id"])
        cash = user_information[0]["cash"]
        return render_template("sell.html", cash = cash)
    else:
        stock_symbol = request.form.get("symbol")
        stock_symbol = stock_symbol.upper()
        shares = request.form.get("shares")
        try:
            shares = int(shares)
        except:
            return apology("Invalid Stock Value Entered (O or Negative)")
        stock_quote = lookup(stock_symbol)
        #validate the stock_quote
        if stock_quote == None:
            return apology("Invalid Stock Name Entered")
        isValid = False
        stock_information = db.execute("SELECT * FROM people_stocks WHERE username_id = (?) AND stock_name = (?)", session["user_id"], stock_symbol)
        for row in stock_information:
            if row["stock_name"] == stock_symbol:
                isValid = True
        if isValid == False:
            return apology("Invalid Stock Name Entered (1)")
        #validate the shares
        if int(shares) <= 0:
            return apology("Invalid Stock Value Entered (O or Negative)")
        stock_information = db.execute("SELECT * FROM people_stocks WHERE username_id = (?) AND stock_name = (?)", session["user_id"], stock_symbol)
        current_shares = stock_information[0]["stock_number"]
        if int(current_shares) < int(shares):
            return apology("Invalid Number Entered")
        #update the user's shares and total_cost
        current_shares = current_shares - int(shares)
        new_cost = current_shares * (stock_quote["price"])
        db.execute("UPDATE people_stocks SET stock_number = (?) WHERE username_id = (?) AND stock_name = (?)", int(current_shares), session["user_id"], stock_symbol)
        db.execute("UPDATE people_stocks SET total_cost = (?) WHERE username_id = (?) AND stock_name = (?)", usd(new_cost), session["user_id"], stock_symbol)
        #get the user's cash value and update it
        user_information = db.execute("SELECT * FROM users WHERE id = (?)", session["user_id"])
        cash = user_information[0]["cash"]
        total_value = float(stock_quote["price"]) * int(shares)
        cash=cash.replace("$","")
        cash=cash.replace(",","")
        cash = float(cash)
        cash = cash + total_value
        db.execute("UPDATE users SET cash = (?) WHERE id = (?)", usd(cash), session["user_id"])
        #add to people_history table
        db.execute("INSERT INTO people_history (username_id, stock_name, stock_number, total_cost, type, stock_price) VALUES (?, ?, ?, ?, ?, ?)", session["user_id"], stock_symbol, shares, usd(total_value), "SELL", usd(stock_quote["price"]))
        return redirect("/")





@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        user_information = db.execute("SELECT * FROM users WHERE id = (?)", session["user_id"])
        #display balance to user
        cash = user_information[0]["cash"]
        cash=cash.replace("$","")
        cash=cash.replace(",","")
        cash = float(cash)
        return render_template("buy.html", cash = usd(cash))
    else:
        #retrieve stock_symbol and shares
        stock_symbol = request.form.get("symbol")
        stock_symbol = stock_symbol.upper()
        shares = request.form.get("shares")
        try:
            shares = int(shares)
        except:
            return apology("Invalid Stock Value Entered (O or Negative)")
        #call lookup function
        stock_quote = lookup(stock_symbol)

        #validate stock_quote value
        if stock_quote == None:
            return apology("Invalid Stock Name Entered")
        #validate the shares
        if int(shares) <= 0:
            return apology("Invalid Stock Value Entered (O or Negative)")
        #validate that the user can purchase the stock at the given number
        user_information = db.execute("SELECT * FROM users WHERE id = (?)", session["user_id"])
        cash = user_information[0]["cash"]
        total_value = stock_quote["price"] * int(shares)
        cash=cash.replace("$","")
        cash=cash.replace(",","")
        cash = float(cash)


        if total_value > cash:
            return apology ("You are BROKE")
        else:
            cash = cash - float(total_value)
            #update the user's cash amount in the users table
            db.execute("UPDATE users SET cash = (?) WHERE id = (?)", usd(cash), session["user_id"])
            #add or update people_stocks table
            in_table = False
            stocks_information = db.execute("SELECT * FROM people_stocks WHERE username_id = (?)", session["user_id"])
            #iterate over stocks_information to decide to add or update
            for row in stocks_information:
                if row["stock_name"] == stock_symbol: #if user has already bought this stock symbol
                    in_table = True
                    current_shares = row["stock_number"] + int(shares)
                    new_cost = current_shares * (stock_quote["price"])
                    #update stock number, and total_cost
                    db.execute("UPDATE people_stocks SET stock_number = (?) WHERE username_id = (?) AND stock_name = (?)", int(current_shares), session["user_id"], stock_symbol)
                    db.execute("UPDATE people_stocks SET total_cost = (?) WHERE username_id = (?) AND stock_name = (?)", usd(new_cost), session["user_id"], stock_symbol)
            #inserts a new row for a new stock symbol if the user has not bought the stock symbol before
            if in_table == False:
                db.execute("INSERT INTO people_stocks (username_id, stock_name, stock_number, total_cost, stock_price) VALUES (?, ?, ?, ?, ?)", session["user_id"], stock_symbol, shares, usd(total_value), usd(stock_quote["price"]))
            #add to people_history table
            db.execute("INSERT INTO people_history (username_id, stock_name, stock_number, total_cost, type, stock_price) VALUES (?, ?, ?, ?, ?, ?)", session["user_id"], stock_symbol, shares, usd(total_value), "BUY", usd(stock_quote["price"]))
            return redirect("/")




@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    rows = db.execute("SELECT * FROM people_history WHERE username_id = (?)", session["user_id"])
    user_information = db.execute("SELECT * FROM users WHERE id = (?)", session["user_id"])
    cash = user_information[0]["cash"]
    return render_template("history.html", cash = cash, rows = rows)




#login page
@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database to validate username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        #checking for invalid username or invalid password
        #first part checks if the username was found
        #second part checks if the hash is the same value
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)
        #If the server validates these, log the user in
        # Remember which user has logged in. Keeps track of information about the user
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")





@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")





@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "GET":
        return render_template("quote.html")
    else:
        stock_symbol = request.form.get("symbol")
        stock_quote = lookup(stock_symbol)
        if stock_quote == None:
            return apology("Invalid Stock Quote")
        return render_template("quote.html", stock_quote = stock_quote)



@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")

    if request.method == "POST":
        username = request.form.get("username")
        #validate that the user did not leave the username box blank
        if username == None:
            return apology("Please enter a valid username")
        if username == '':
            return apology("Please enter a valid username")
        #validate the username does not match any of the usernames in the user table
        rows = db.execute("SELECT * FROM users")
        for row in rows:
            if row["username"] == username:
                return apology("Username is already taken")
        password = str(request.form.get("password"))
        #validate that the user did not leave the password box blank
        if password == None or password == '':
            return apology("Please enter a valid password")
        confirm_password = request.form.get("confirmation")
        if confirm_password == None or confirm_password == '':
            return apology("INVALID")
        if password != confirm_password:
            return apology("Please match the passwords")
        #hash the password
        hash_value = generate_password_hash(password)
        #insert the password into the database
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash_value)
        rows = db.execute("SELECT * FROM users")
        return render_template("login.html")