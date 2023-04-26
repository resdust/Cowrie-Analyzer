import json
import operator
import glob
import os
import matplotlib.pyplot as plt
from dateutil.parser import parse
from datetime import timedelta
from collections import defaultdict


def bin_by_hours(given_time, bin_amt):
    return given_time - timedelta(hours=given_time.hour % bin_amt, minutes=given_time.minute,
                                  seconds=given_time.second, microseconds=given_time.microsecond)


def bin_by_minutes(given_time, bin_amt):
    return given_time - timedelta(minutes=given_time.minute % bin_amt, seconds=given_time.second, microseconds=given_time.microsecond)


# does a quick analysis of cowrie json logs, and prints some details to stdout
# currently prints the total number of telnet and ssh attempts
# top 10 IPs that attempt logins
# top 10 username attempts
# top 10 password attempts
# top 10 username:password combo attempts
class CowrieAnalyzer:
    def __init__(self, json_dir='log'):
        self.ROOT_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        print("json_dir: " + os.path.join(json_dir, 'cowrie*.json'))
        # self.files = glob.glob(json_dir + os.sep + '*.json')
        self.files = glob.glob(os.path.join(self.ROOT_PATH, json_dir, 'cowrie*.json'))
        self.num_ssh, self.num_telnet = 0, 0
        self.src_ip_cnt = defaultdict(int)  # defaultdict, so no special case for the first instance of a count
        self.username_cnt = defaultdict(int)
        self.pass_cnt = defaultdict(int)
        self.userpass_cnt = defaultdict(int)
        self.ssh_times_cnt = defaultdict(int)
        self.telnet_times_cnt = defaultdict(int)
        self.geoip_lookup = defaultdict(int)
        self.whitelist = ['192.168.100.100', '192.168.16.51', '192.168.16.50', '127.0.0.1']

    def plot(self, data, 
             title = 'Attack Attempts per Day', 
             xlabel = 'Time', 
             ylabel= 'SSH Attempts', 
             type='line'):
        fig = plt.figure()
        ax = fig.add_subplot(111)
        ax.set_xlabel(xlabel)
        ax.set_ylabel(ylabel)
        ax.set_title(title)
        if type == 'line':
            x_data, y_data = zip(*sorted(data.items()))
            ax.plot(x_data, y_data, 'b-')
            fig.autofmt_xdate()
        elif type == 'bar':
            x_data, y_data = zip(*sorted(data.items(), key=lambda x: x[1]))
            x_data = x_data[-10:]
            y_data = y_data[-10:]
            # print(x_data, y_data)

            fig.subplots_adjust(left=0.4)

            plt.barh(x_data, y_data)
            plt.yticks(rotation=30)
        # dates, telnet_attempts = zip(*sorted(self.telnet_times_cnt.items()))
        # ax.plot(dates, telnet_attempts, 'r-', label='Telnet Attempts')
        # ax.legend()
        # plt.show()
        plt.title(title)
        fig_name = title.replace(' ', '_') + '.png'
        fig_name = os.path.join(self.ROOT_PATH,'Cowrie-Analyzer' ,'img', fig_name)
        print("saving figure to " + os.path.basename(fig_name))
        fig.savefig(fig_name)

    def run(self):
        print('analyzing ' + str(len(self.files)) + ' files')
        total_contents = []
        for file in self.files:
            with open(file) as openfile:
                for line in openfile:
                    total_contents.append(json.loads(line))

        num_ssh, num_telnet = 0, 0
        for event in total_contents:
            if 'cowrie.login' in event['eventid']:
                if event['src_ip'] in self.whitelist:
                    continue
                # only ssh
                num_ssh += 1
                time = bin_by_hours(parse(event['timestamp']), 24)
                self.ssh_times_cnt[time] += 1

                # if 'SSH' in event['system']:
                #     num_ssh += 1
                #     time = bin_by_hours(parse(event['timestamp']), 24)
                #     self.ssh_times_cnt[time] += 1
                # elif 'Telnet' in event['system']:
                #     num_telnet += 1
                #     time = bin_by_hours(parse(event['timestamp']), 24)
                #     self.telnet_times_cnt[time] += 1

                self.src_ip_cnt[event['src_ip']] += 1
                self.username_cnt[event['username']] += 1
                self.pass_cnt[event['password']] += 1
                self.userpass_cnt[event['username'] + ':' + event['password']] += 1

        print('telnet attempts: ' + str(num_telnet))
        print('SSH attempts:' + str(num_ssh))
        print('most common source addresses:')
        for addr in sorted(self.src_ip_cnt.items(), key=operator.itemgetter(1), reverse=True)[:10]:
            print(addr)
        print('most common username attempts:')
        for user in sorted(self.username_cnt.items(), key=operator.itemgetter(1), reverse=True)[:30]:
            print(user)
        print('most common password attempts:')
        for passw in sorted(self.pass_cnt.items(), key=operator.itemgetter(1), reverse=True)[:30]:
            print(passw)
        print('most common username/password combos:')
        for creds in sorted(self.userpass_cnt.items(), key=operator.itemgetter(1), reverse=True)[:10]:
            print(creds)

        self.plot(data = self.ssh_times_cnt, ylabel = 'SSH Attempts', type='line')
        self.plot(data = self.username_cnt, 
             title = 'Top 10 Username Attempts', 
             xlabel = 'Count', 
             ylabel= 'Username', 
             type='bar')
        self.plot(data = self.pass_cnt, 
             title = 'Top 10 Password Attempts', 
             xlabel = 'Count', 
             ylabel= 'Password', 
             type='bar')
        self.plot(data = self.userpass_cnt, 
             title = 'Top 10 Username-Password Pair', 
             xlabel = 'Count', 
             ylabel= 'Username-Password', 
             type='bar')
        if os.path.isfile('GeoLite2-Country.mmdb'):
            self.map_ips()

    def map_ips(self):
        geoip_overall = defaultdict(int)
        import geoip2.database
        reader = geoip2.database.Reader('GeoLite2-Country.mmdb')
        for addr in sorted(self.src_ip_cnt.items(), key=operator.itemgetter(1), reverse=True):
            response = reader.country(addr[0])
            self.geoip_lookup[response.country.name] += 1  # or += addr[1]
            geoip_overall[response.country.name] += addr[1]
        print('unique source IPs:')
        print(len(self.src_ip_cnt))
        print('unique countries for source IPs:')
        print(len(self.geoip_lookup))
        print('most common countries for source IPs:')
        for country in sorted(self.geoip_lookup.items(), key=operator.itemgetter(1), reverse=True)[:10]:
            print(country)
        print('unique countries for overall attacks:')
        print(len(geoip_overall))
        print('most common countries for overall attacks:')
        for country in sorted(geoip_overall.items(), key=operator.itemgetter(1), reverse=True)[:10]:
            print(country)


# run from the command line
if __name__ == '__main__':
    CowrieAnalyzer(json_dir='24032023_COWRIE_LOGS').run()
