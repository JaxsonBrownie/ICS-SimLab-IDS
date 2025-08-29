from datetime import timezone
import datetime

# print to file timestamping when attack starts
dt = datetime.datetime.now(timezone.utc)
formatted_time = dt.strftime('%H:%M:%S') + f'.{dt.microsecond}'

print(formatted_time)