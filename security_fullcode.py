##Pby-Harfho

from cyber import *

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