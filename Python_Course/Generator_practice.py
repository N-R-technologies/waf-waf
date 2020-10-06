"""simple examples of using generators and generators function. we used it for printing all the dates exist"""
def gen_secs():
    return (second for second in range(0,60))

def gen_minutes():
    return (minute for minute in range(0, 60))

def gen_hours():
    return (hour for hour in range(0, 24))

def gen_time():
    return (str(hour) + ":" + str(minute) + ":" + str(second) for hour in gen_hours() for minute in gen_minutes() for second in gen_secs())

def gen_years(start=2020):
    while True:
        yield start
        start = start + 1

def gen_months():
    return (month for month in range(1,13))

def gen_days(month, leap_year=True):
    max_days = 0
    if (month % 2 == 1 and month < 8) or  (month >= 8 and month % 2 == 0):
        max_days = 32
    elif month == 2:
        if leap_year:
            max_days = 30
        else:
            max_days = 29
    else:
        max_days = 31
    return (days for days in range(0, max_days))

def gen_date():
    while True:
        for year in gen_years():
            if (year % 4 == 0) or (year % 100 == 0 and year % 400 == 0):
                leap_year = True
            else:
                leap_year = False
            for month in gen_months():
                for day in gen_days(month, leap_year):
                    for time in gen_time():
                        yield str(day) + "/" + str(month) + "/" + str(year) + " " + time

def main():
    gd = gen_date()
    for i  in range(0,1000000):
        gd.__next__()
    print(gd.__next__())
    for i  in range(0,1000000):
        gd.__next__()
    print(gd.__next__())
    for i  in range(0,1000000):
        gd.__next__()
    print(gd.__next__())



if __name__ == "__main__":
    main()