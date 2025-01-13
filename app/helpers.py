import time

def delay_to_min_required_delay(min_duration, start_time):
    elapsed_time = time.time() - start_time
    left_to_sleep = min_duration - elapsed_time
    if left_to_sleep > 0:
        time.sleep(left_to_sleep)