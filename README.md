Trusted Sleep Bot
==================

This bot records one's sleep time via online status on Telegram.

Features
--------

* Fully timezone aware
* Telegram Bot API and telegram-cli dual stack
* Multiple ways to determine online status
* Can compare among group members

Commands
--------

* /status \[all|@username] - List sleeping status
* /average - List statistics about sleep time
* /subscribe - Add you to the watchlist
* /unsubscribe - Remove you from the watchlist
* /settz - Set your timezone
* /help - Show usage


Algorithm
---------

```
-24h    0           6   now
   /=====================\  <- SELECT
   .  x-+-----------+----💤?
   .    |     x-----+----💤?
   .    |           | x  🌞?
   .  x-+--------x x| xx
   .  x-+-----------+--x
   .  xx| x------x x| xx
   .    | x x-------+-x
   .  x |    x------+--x
   .  x | x-------x |    🌞?
 x .    |           |    🌞?
   . x  |           |  x 🌞?

Legend:
x	user event
.	select boundary (last 24h)
-	sleep duration
|	cut window (local time)
💤	maybe sleeping
🌞	maybe awake
```

**How this bot works**

1. `SELECT` user events in last 24h from the database, ordered by time
2. Convert the cut window (config: `cutwindow`) to user's local time
3. Select the last event before the cut window (if any)
4. Select all events inside the cut window
5. Select the first event after the cut window if there are events before or inside the cut window (if any)
6. For each selected event pair:
    * If nothing selected: **Status unknown, maybe awake**
    * If only one event:
        * If current time is not later than the start time by 12h (config: `threshold`), report **start time**, **maybe asleep**.
        * Else, report **status unknown, maybe awake**.
    * Else: select the longest interval between the events.
        * If the interval is not longer than 12h, report **sleep** time as the two events.
        * Else, report **status unknown, maybe awake**.
7. If the sleep time can be determined, `REPLACE INTO` the `sleep` table.
8. (Optional) Clean old events.

**Note**: This bot will not be accurate when a user chooses to hide his/her online status.

License
-------
MIT License.
