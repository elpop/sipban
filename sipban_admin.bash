#!/bin/bash
#
# Use this iptables rules to use the script:
#
# /sbin/iptables -t filter -I INPUT -i eno1 -m set --match-set sipban src -j DROP

# Your ipset data set name
IPSET_NAME="sipban"
SAVE_FILE="/etc/sipban.dump"
TIMEOUT=604800
IPv4="^((25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))(\/(3[0-2]|[1-2][0-9]|[1-9]))?$"

case $1 in
    # create set
    -c)
        /usr/sbin/ipset create $IPSET_NAME hash:net hashsize 4096 timeout $TIMEOUT > /dev/null
    ;;
    # Flush (empty) the set
    -f)
        /usr/sbin/ipset flush $IPSET_NAME
    ;;
    # Kill (Destroy) the set
    -k)
        /usr/sbin/ipset destroy $IPSET_NAME
    ;;
    # info of the set
    -i)
        /usr/sbin/ipset list $IPSET_NAME -t
    ;;
    # add ip to set
    -a)
        if [[ $2  =~ $IPv4 ]]; then
            /usr/sbin/ipset -q add $IPSET_NAME $2 > /dev/null
        else
            echo 'Invalid ip address'
        fi
    ;;
    # Delete ip from set
    -d)
        if [[ $2  =~ $IPv4 ]]; then
            /usr/sbin/ipset del $IPSET_NAME $2
        else
            echo 'Invalid ip address'
        fi
    ;;
    # list ip's on set
    -l)
        if  [[ $2  =~ $IPv4 ]]; then
            /usr/sbin/ipset test $IPSET_NAME $2
        else
            /usr/sbin/ipset list $IPSET_NAME
        fi
    ;;
    # Save set to file
    -s)
        /usr/sbin/ipset save $IPSET_NAME > $SAVE_FILE
    ;;
    # Restore set from file
    -r)
        /usr/sbin/ipset restore -! < $SAVE_FILE
    ;;
    # Upload ip's from given file
    -u)
        if test -f $2; then
            while IFS= read -r line;
                do
                    if [[ $line  =~ $IPv4 ]]; then
                        /usr/sbin/ipset -q add $IPSET_NAME $line > /dev/null
                    else
                        echo 'Invalid ip address'
                    fi
                done < $2
        fi
    ;;
    # show options if not flag
    *)
        echo "Usage: $0 [options]"
        echo 'options:'
        echo '    -c (create sipban set)'
        echo '    -f (flush ipset members)'
        echo '    -k (destroy sipban set)'
        echo '    -i (info of sipban set)'
        echo
        echo '    -a [ip] or [ip/class] (add ip or ip/class to sipban set)'
        echo '    -d [ip] (delete ip from sipban set)'
        echo '    -l {ip} (list members or test a given ip)'
        echo
        echo '    -s (save to sipban file)'
        echo '    -r (restore from sipban file)'
        echo '    -u [file] (upload from a given file)'
        exit 1
    ;;
esac
