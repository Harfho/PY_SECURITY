import nmap
import socket
import os
import sys


#----------USERVALIDATE---------
def Uservalidate():
    user_pass = {}

    username = input('Enter  username: ')

    while not username :
        print("\tError 'Enter valid Username'")
        username = input('Enter  username: ')
        if username:
            break
        else:
            continue
        
        
    password= input('Enter password: ')

    user_pass[username]=password
            

    if username in user_pass.keys():
        tried = 1
        confirm_password= input('Confirm password: ')
        while tried <=3:
            if confirm_password != user_pass[username] :
                print('Password is not correct\nHave %s more time to try again' % (3-tried))
                tried += 1
                confirm_password= input('Confirm password: ')
            else:
                Allow = True
                print('\n\n\t\t-------Password correct------')
                break
        else:
            Allow = False
            print("Sorry 'Password is not correct'")
        
        return Allow

#----------------------run a port scan on a giving ip address fuc---------

def Find_ip (host_address,port_range = '1-100'):
    
    
    hostaddress = host_address
    portrange = port_range

    print("------"*4+
                    "Scanning Port" +
          "-------"*4+
          "\n\t|||||| Host/ip - (%s) \t|||||| port range - (%s)"
          %(hostaddress,portrange)
            )
    
    try:
        ipaddress = socket.gethostbyname(hostaddress)
    except socket.gaierror as socketerror:
        print("--------------"*6)
        error_msg = """ Can not connect to the server/Internet - "Connect to the server/Internet and 'try again'"
                        """.title()
        print( error_msg)
        
    print("--------------"*6)
    try:
        print('     please wait Scanning The Host %s ( %s )'%( hostaddress , ipaddress))
    except:
        print(' error')
    print("--------------"*6)

    netscan = nmap.PortScanner()
    netscan.scan(hostaddress,portrange)
    print("--------------"*6)
    print(netscan.scaninfo())
    print("--------------"*6)

    print(netscan.csv())

    print('---------'*5+'additional_info'+'---------'*5)
    print('If there is any additional info for you to see,You will see it below')
    for host in netscan.all_hosts():
        print("     Host : %s (%s)" % (host,hostaddress))
        print("     State : %s" % netscan[host].state())
        
        for proto in netscan[host].all_protocols():
            print("--------------"*8)
            print("     protocols : %s" % proto)
            
            lport = netscan[host][proto].keys()
            sorted(lport)
            for port in lport:
                print("     Port : %s \t State %s" % (port,netscan[host][proto][port]["state"]))



##-------------- NETSTAT COMMAND-----------
                
def Netstat():
    msg = """
        ---------------------------------------------------------------------------
        Displays protocol statistics and current TCP/IP network connections.

        NETSTAT [-a] [-b] [-e] [-f] [-n] [-o] [-p proto] [-r] [-s] [-x] [-t] [interval]

          -a            Displays all connections and listening ports.
          -b            Displays the executable involved in creating each connection or
                        listening port. In some cases well-known executables host
                        multiple independent components, and in these cases the
                        sequence of components involved in creating the connection
                        or listening port is displayed. In this case the executable
                        name is in [] at the bottom, on top is the component it called,
                        and so forth until TCP/IP was reached. Note that this option
                        can be time-consuming and will fail unless you have sufficient
                        permissions.
          -e            Displays Ethernet statistics. This may be combined with the -s
                        option.
          -f            Displays Fully Qualified Domain Names (FQDN) for foreign
                        addresses.
          -n            Displays addresses and port numbers in numerical form.
          -o            Displays the owning process ID associated with each connection.
          -p proto      Shows connections for the protocol specified by proto; proto
                        may be any of: TCP, UDP, TCPv6, or UDPv6.  If used with the -s
                        option to display per-protocol statistics, proto may be any of:
                        IP, IPv6, ICMP, ICMPv6, TCP, TCPv6, UDP, or UDPv6.
          -r            Displays the routing table.
          -s            Displays per-protocol statistics.  By default, statistics are
                        shown for IP, IPv6, ICMP, ICMPv6, TCP, TCPv6, UDP, and UDPv6;
                        the -p option may be used to specify a subset of the default.
          -t            Displays the current connection offload state.
          -x            Displays NetworkDirect connections, listeners, and shared
                        endpoints.
          -y            Displays the TCP connection template for all connections.
                        Cannot be combined with the other options.
          interval      Redisplays selected statistics, pausing interval seconds
                        between each display.  Press CTRL+C to stop redisplaying
                        statistics.  If omitted, netstat will print the current
                        configuration information once.
            ---------------------------------------------------------------------------
            
            Enter Option: """

    command = input(msg)

    command_valid = ['-a','-b','-e','-f','-n','-o','-p proto','-r','-s','-t','-x','-y',"interval","proto"]

    while True:
            command = input("\t  Enter a valid NETSTAT options [-a] [-b] [-e] [-f] [-n] [-o] [-p proto] [-r] [-s] [-x] [-t] [interval]: ")
            if command in command_valid:
                break
            elif command not in  command_valid:
                continue
     


    netstat = os.popen(f'netstat {0}'.format(command)).read()
    print("\n Connections",netstat)




##_________________SHUTDOWN or RESTART________________________
def Shut_down():
    print("\t1. Shutdown")
    print("\t2. Restart")
    
    while True:
        choice_opt = ['1','2']
        choice_exit = ['0','',' ','q','Q','e','E']
        try:
            choice = input('\t\tEnter Option: ')
            if choice in choice_exit:
                print('\t\t-------EXIT-------')
                break
            elif choice not in  choice_opt:
                    print('Enter valid  value (1|2):')
                    continue
            else:
                choice = int(choice)
                break
        except ValueError:
            print('Enter a valid option')
            continue
    
    #check OS platfrom
    if sys.platform == 'linux' or sys.platform == "linux2":
        pass
    elif sys.platform == 'darwin':
        pass
    elif sys.platform == "win32":
        if choice == 1:
                os.system("shutdown /s /t 0")
        elif choice == 2:
                os.system("shutdown /r /t 0")
    else:
        print("OS Error")




##---------main------

user = Uservalidate()
if user:
    menu_msg = """
    ----------------------------------------------------------------
            \t'Enter number to select options "(4) to exit" '
            
            1. Run a port Scan on a given ip address using python-nmap.
            2. Run Netstat.
            3. Shut_down or Restart.
            4. Exit program.
    -----------------------------------------------------------------      
            
            Enter option: """
    
    
    flag = True
    while flag:
        menu_itm = [1,2,3,4]
        menu_exit = ['0','',' ','q','Q','e','E']
        try:
            menu = input(menu_msg)
            if menu in menu_exit or menu==False :
                menu = int(menu)
                print('\t\t-------EXIT-------')
                break
            elif int(menu) not in menu_itm:
                print('Enter a number <=3')
                continue
            else:
                flag=False
        except ValueError:
            print('Invalid option')
            continue
    
    if int(menu) == 1:
        print("\t\tRun a port Scan on a given ip address using python-nmap.")
        hostaddress =str(input("Enter Host Address: "))
        flag = True
        while flag:
            try:
                portrange = input("Enter Port Scanning Range (Default = 1-100): ")
                break
            except TypeError:
                print('Invalid option,Enter a valid number (1 - n )')
                continue
        
        if portrange:
            Find_ip(hostaddress,portrange)
        else:
            Find_ip(hostaddress)
    
    elif int(menu)==2:
        Netstat()
        
    elif int(menu)==3:
        Shut_down()
        
    elif int(menu)==4:
        sys.exit()
input('DONE')