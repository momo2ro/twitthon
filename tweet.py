#!/usr/bin/python3
# coding: utf-8
from argparse import ArgumentParser
from os import path
from twitter_oauth import TwitterAuthorizer
from twitter_oauth import TwitterSession
import sys
import mybase64


def parser():
    parser = ArgumentParser(description="Simple Twitter client can only tweet(Default is GUI)")
    parser.set_defaults(func=main_command)
    parser.add_argument("-m", "--main",
                        dest="screen_name",
                        help="change main account")
    subparsers = parser.add_subparsers(dest="flag", help="sub-command help")
    parser_authorize = subparsers.add_parser("authorize",
                                             help="authorize twitter OAuth")
    parser_authorize.set_defaults(func=authorize)
    auth_group = parser_authorize.add_mutually_exclusive_group(required=True)
    auth_group.add_argument("-f", "--from_file",
                            action="store_true",
                            help="reauthorize from .credentials file")
    auth_group.add_argument("-c", "--client",
                            nargs=2,
                            metavar=("KEY", "SECRET"),
                            help="set client credential")
    parser_authorize.add_argument("-t", "--token",
                                  nargs=2,
                                  metavar=("KEY", "SECRET"),
                                  help="set token credential")
    parser_tweet = subparsers.add_parser("tweet",
                                         description="tweet from arg or stdin",
                                         help="send tweet")
    parser_tweet.set_defaults(func=shell_tweet)
    parser_tweet.add_argument("text", nargs="?")
    parser_tweet.add_argument("-m", "--media",
                              dest="file_path",
                              nargs="+",
                              help="tweet with media(max:4)")
    parser_tweet.add_argument("-at",
                              dest="screen_name",
                              nargs="+",
                              help="send reply")
    parser_tweet.add_argument("-ac", "--account",
                              dest="account_name",
                              help="change account")
    parser_message = subparsers.add_parser("message",
                                           description="direct message from arg or stdin",
                                           help="send direct message")
    parser_message.set_defaults(func=shell_message)
    parser_message.add_argument("text", nargs="?")
    to_group = parser_message.add_mutually_exclusive_group(required=True)
    to_group.add_argument("-n", "--screen_name",
                          help="set screen name")
    to_group.add_argument("-i", "--id", type=int,
                          dest="user_id",
                          help="set id")
    parser_message.add_argument("-m", "--media",
                                dest="file_path",
                                nargs="+",
                                help="send base64 encoded file")
    parser_message.add_argument("-ac", "--account",
                                dest="account_name",
                                help="change account")
    parser_gui = subparsers.add_parser("gui",
                                       help="tweet graphical")
    parser_gui.set_defaults(func=gui_tweet)
    args = parser.parse_args()
    if args.flag in ["tweet", "message"] and not args.text:
        args.text = sys.stdin.read().rstrip("\n")
    args.func(args)


def __get_credentials_cache(screen_name=None, get_all=False, ignore=False):
    cache_path = path.abspath(path.dirname(__file__)) + "/.credentials.csv"
    if path.exists(cache_path):
        with open(cache_path) as f:
            credentials = tuple(x.rstrip("\n").split(",") for x in f)
    elif ignore:
        return None
    else:
        print("Credentials file not found. Authorize again.", file=sys.stderr)
        sys.exit(1)
    keys = credentials[0]
    credential_dict = [dict(zip(keys, x)) for x in credentials[1:]]
    if get_all:
        return credential_dict
    elif not screen_name:
        return credential_dict[0]
    else:
        for line in credential_dict:
            if screen_name != line["screen_name"]: continue
            return line
        else:
            print("{0} not found in credentials file.".format(screen_name), file=sys.stderr)
            sys.exit(1)


def __write_credentials_cache(consumer_key,
                              consumer_secret,
                              access_token,
                              access_token_secret,
                              user_id,
                              screen_name,
                              overwrite=False):
    element_lst = [consumer_key, consumer_secret, access_token, access_token_secret, user_id]
    if bool(screen_name):
        element_lst.append(screen_name)
    addiction_line = ",".join(element_lst)
    cache_path = path.abspath(path.dirname(__file__)) + "/.credentials.csv"
    write_flag = "w" if overwrite else "a"
    write_flag = "w" if not path.exists(cache_path) else write_flag
    with open(cache_path, write_flag) as f:
        if write_flag == "w":
            print(",".join(["consumer_key",
                            "consumer_secret",
                            "access_token",
                            "access_token_secret",
                            "user_id",
                            "screen_name"]), file=f)
        print(addiction_line, file=f)


def __overwrite_credentials_cache(credentials):
    for count, line in enumerate(credentials):
        __write_credentials_cache(line["consumer_key"],
                                  line["consumer_secret"],
                                  line["access_token"],
                                  line["access_token_secret"],
                                  line["user_id"],
                                  line["screen_name"],
                                  not count)


def authorize(args):
    if args.from_file:
        consumer_key, consumer_secret = __get_credentials_cache().values()[:2]
    else:
        consumer_key, consumer_secret = args.client
    if args.token:
        access_token, access_token_secret = args.token
    else:
        authorizer = TwitterAuthorizer(consumer_key, consumer_secret)
        print("Please access to this url: " + authorizer.get_authorization_url())
        pin = input("And input pin code: ")
        access_token, access_token_secret = authorizer.get_token(pin)
    session = TwitterSession(consumer_key,
                             consumer_secret,
                             access_token,
                             access_token_secret)
    user_obj = session.account_verify_credentials()
    user_id = user_obj["id_str"]
    screen_name = user_obj["screen_name"]
    credentials = __get_credentials_cache(get_all=True, ignore=True)
    if credentials is not None:
        user_id_lst = [x["user_id"] for x in credentials]
    if credentials is None or user_id not in user_id_lst:
        __write_credentials_cache(consumer_key,
                                  consumer_secret,
                                  access_token,
                                  access_token_secret,
                                  user_id,
                                  screen_name)
    else:
        index = user_id_lst.index(user_id)
        credentials[index]["consumer_key"]        = consumer_key
        credentials[index]["consumer_secret"]     = consumer_secret
        credentials[index]["access_token"]        = access_token
        credentials[index]["access_token_secret"] = access_token_secret
        credentials[index]["screen_name"]         = screen_name
        __overwrite_credentials_cache(credentials)
    print("Authorization successful!")


def shell_tweet(args):
    credentials = __get_credentials_cache(screen_name=args.account_name)
    session = TwitterSession(credentials["consumer_key"],
                             credentials["consumer_secret"],
                             credentials["access_token"],
                             credentials["access_token_secret"])
    if bool(args.screen_name):
        args.text = " ".join("@" + x for x in args.screen_name) + " " + args.text
    if bool(args.file_path):
        if len(args.file_path) > 4:
            print("Media upload limit is 4 by once!", file=sys.stderr)
            sys.exit(1)
        media_ids = [session.media_upload(x) for x in args.file_path]
        session.status_update(args.text, media_ids)
    else:
        session.status_update(args.text)
    print("Tweet successful!")


def shell_message(args):
    credentials = __get_credentials_cache(screen_name=args.account_name)
    session = TwitterSession(credentials["consumer_key"],
                             credentials["consumer_secret"],
                             credentials["access_token"],
                             credentials["access_token_secret"])
    if bool(args.file_path):
        for p in args.file_path:
            with open(p, "br") as f:
                file_data = b"".join(x for x in f)
            encoded_data = mybase64.byte_encode(file_data)
            session.direct_message_new(p + " encoded base64", args.screen_name, args.user_id)
            print(len(encoded_data))
            for split_data in [encoded_data[i: i+10000] for i in range(0, len(encoded_data), 10000)]:
                session.direct_message_new(split_data, args.screen_name, args.user_id)
    session.direct_message_new(args.text, args.screen_name, args.user_id)
    print("Message successful!")


def main_command(args):
    if args.screen_name:
        change_main(args.screen_name)
    else:
        gui_tweet(args)


def change_main(screen_name):
    credentials = __get_credentials_cache(get_all=True)
    for count, line in enumerate(credentials):
        if line["screen_name"] != screen_name: continue
        break
    else:
        print("{0} not found in credentials file.".format(screen_name), file=sys.stderr)
        sys.exit(1)
    credentials.insert(0, credentials.pop(count))
    __overwrite_credentials_cache(credentials)


def gui_tweet(args):
    print("出来ません")  # kari

if __name__ == "__main__":
    parser()
