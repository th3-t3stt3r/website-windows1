from time import sleep
import time
import psutil
from os import system


#process = psutil.Process(2006287).io_counters()
#process = psutil.Process(2006287).cmdline()
#process = psutil.Process(2006180).is_running()
#process = psutil.Process(2006180).create_time()
#process = psutil.Process(2006180).nice()
#process = psutil.Process(2315363).memory_full_info()
#process = psutil.Process(2315363).ionice()
#process = psutil.Process(2463529).num_threads()
#process = psutil.Process(2611741).rlimit()

# plist = psutil.process_iter()
# print(process)
# for process in plist:
#     print(process)

p = psutil.Process(196232)
startbytes = p.io_counters().write_bytes
cpucount = psutil.cpu_count()


start = time.perf_counter()

print(f"Start bytes: {startbytes}")
for i in range(1, 21):
    print(p.cpu_percent() / cpucount)
    new_bytes = p.io_counters().write_bytes
    print(f"New bytes: {new_bytes}")
    print(i / 2)
    sleep(0.5)
    if i == 10:
        pass
    else:
        system('clear')

end = time.perf_counter()
print(f"Took {round(end - start,3)}")
print(startbytes)
print(f"Bytes difference: {new_bytes - startbytes}")

# cryptocapy = 24mi bytes em 10s
