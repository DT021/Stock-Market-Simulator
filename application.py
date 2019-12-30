import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    stocks = db.execute(
        "SELECT symbol, SUM(shares) as total_shares FROM transactions WHERE id = :user_id GROUP BY symbol HAVING total_shares > 0", user_id=session["user_id"])

    # get the current amount of cash in the user's account
    current_cash = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])
    current_cash = current_cash[0]["cash"]

    # dictionary for storing stocks data
    quotes = {}
    # the total amount of cash the user owned from beginning
    total = current_cash

    for stock in stocks:
        quotes[stock["symbol"]] = lookup(stock["symbol"])
        total += quotes[stock["symbol"]]["price"] * stock["total_shares"]

    return render_template("index.html", total=total, quotes=quotes, stocks=stocks, current_cash=current_cash)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        # search for the entered symbol
        quote = lookup(request.form.get("symbol"))
        # make sure that the symbol exists
        if not quote:
            return apology("symbol does not exist", 400)

        # check if shares number is a positive integer
        if request.form.get("shares").isdigit() == False or int(request.form.get("shares")) <= 0:
            return apology("shares number must be a positive integer", 400)

        # check if user has enough money to buy stocks
        current_cash = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])
        shares_price = quote["price"] * int(request.form.get("shares"))

        # make sure the user has enough money to buy the shares
        if current_cash[0]["cash"] < shares_price:
            return apology("you do not have enough cash", 400)

        db.execute("UPDATE users SET cash = cash - :shares_price WHERE id = :user_id", shares_price=shares_price, user_id=session["user_id"])
        db.execute("INSERT INTO transactions (id, symbol, shares, price) VALUES(:user_id, :symbol, :shares, :price)",
                   user_id=session["user_id"],
                   symbol=request.form.get("symbol"),
                   shares=int(request.form.get("shares")),
                   price=quote["price"])


        flash("Bought!")
        return redirect("/")

    # if user arrived via GET
    else:
        return render_template("buy.html")


@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""

    # get username
    username=request.args.get("username")
    rows = db.execute("SELECT * FROM users WHERE username = :username",
                      username=username)
    if len(rows) != 1 and len(username) > 0:
        return jsonify(True)
    # False
    return jsonify(False)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    transactions = db.execute(
        "SELECT symbol, shares, price, created_at FROM transactions WHERE id = :user_id ORDER BY created_at ASC", user_id=session["user_id"])

    return render_template("history.html", transactions=transactions)


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

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # if user arrived via GET
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
    """Get stock quote."""
    if request.method == "POST":
        # search for the entered symbol
        quote = lookup(request.form.get("symbol"))
        # make sure that the symbol exists
        if not quote:
            return apology("symbol does not exist", 400)

        else:
            return render_template("quoted.html", name=quote["name"], symbol=quote["symbol"], price=usd(quote["price"]))

    # if user arrived via GET
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # forget any user_id
    session.clear()

    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username", 400)

        elif not request.form.get("password"):
            return apology("must provide password", 400)

        elif not request.form.get("confirmation"):
            return apology("must provide password confirmation", 400)

        if request.form.get("password") != request.form.get("confirmation"):
            return apology("paswords must match")

        # store the hash of the password
        hash = generate_password_hash(request.form.get("password"))

        # insert the username and password into the database
        result = db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)",
        username=request.form.get("username"),
        hash=hash)

        # return an apology if username already exists
        if not result:
            return apology("username already taken", 400)

        # login user automatically and remember session
        session["user_id"] = result

        # Display a flash message
        flash("Registered!")

        # redirect to login page
        return redirect("/")

    # if user arrived via GET
    else:
        return render_template("register.html")


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    """Allow users to change the password"""

    if request.method == "POST":

        if not request.form.get("current_password"):
            return apology("must provide current password", 400)

        # Query database for user_id
        rows = db.execute("SELECT hash FROM users WHERE id = :user_id", user_id=session["user_id"])

        # Ensure current password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("current_password")):
            return apology("invalid password", 400)

        # Ensure new password is not empty
        if not request.form.get("new_password"):
            return apology("must provide new password", 400)

        # Ensure new password confirmation is not empty
        elif not request.form.get("new_password_confirmation"):
            return apology("must provide new password confirmation", 400)

        # Check if new password and confirmation are identical
        elif request.form.get("new_password") != request.form.get("new_password_confirmation"):
            return apology("new password and confirmation must match", 400)

        # Update database with the new password
        hash = generate_password_hash(request.form.get("new_password"))
        db.execute("UPDATE users SET hash = :hash WHERE id = :user_id", user_id=session["user_id"], hash=hash)

        flash("Password was changed!")

        return redirect("/")

    # if user arrived via GET
    else:
        return render_template("change_password.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "POST":
        quote = lookup(request.form.get("symbol"))
        if not quote:
            return apology("must provide stock symbol", 400)

        shares = int(request.form.get("shares"))
        if not shares:
            return apology("must provide shares number", 400)

        # check if shares number is a positive integer
        if request.form.get("shares").isdigit() == False or shares <= 0:
            return apology("shares number must be a positive integer", 400)

        stock = db.execute("SELECT SUM(shares) as total_shares FROM transactions WHERE id = :user_id AND symbol = :symbol GROUP BY symbol",
                           user_id=session["user_id"], symbol=request.form.get("symbol"))

        # check if enough shares to sell
        if len(stock) != 1 or stock[0]["total_shares"] < shares:
            return apology("please enter a reasonable amount of shares", 400)

        share_price = quote["price"]

        # Calculate the price of requested shares
        total = share_price * shares

        db.execute("UPDATE users SET cash = cash + :price WHERE id = :user_id", price=total, user_id=session["user_id"])
        db.execute("INSERT INTO transactions (id, symbol, shares, price) VALUES(:user_id, :symbol, :shares, :price)",
                   user_id=session["user_id"],
                   symbol=request.form.get("symbol"),
                   shares=-shares,
                   price=share_price)


        flash("Sold!")

        return redirect("/")

    # if user arrived via GET
    else:

        stocks = db.execute("SELECT symbol FROM transactions WHERE id = :user_id GROUP BY symbol HAVING SUM(shares) > 0", user_id=session["user_id"])

        return render_template("sell.html", stocks=stocks)


def errorhandler(e):
    """Handle error"""
    return apology(e.name, e.code)


# listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
