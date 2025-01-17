# Feeds to Bag

_This is just an idea at the moment, a work not even in progress. I am hoping it won't be that hard to take the existing pocket implementation and make it work for Wallabag_

<b>Feeds to Bag</b> watches your RSS and Atom feeds
and pushes new items to your [Wallabag][wallabag] list.

[wallabag]: https://www.wallabag.it/en

## License

<b>Feeds to Bag</b> is licensed
under the terms of either the [MIT license][license-mit]
or the [Apache License, version 2.0][license-apache], at your option.
<b>Feeds to Bag</b> also uses third party libraries,
some of which have different licenses.

### Contribution

Unless you explicitly state otherwise,
any contribution intentionally submitted for inclusion in the work by you,
as defined in the Apache-2.0 license,
shall be dual licensed as above,
without any additional terms or conditions.

[license-mit]: LICENSE-MIT
[license-apache]: LICENSE-APACHE

## Prerequisites

<b>Feeds to Bag</b> uses [OpenSSL][openssl] for HTTPS requests.
If you don't have OpenSSL,
you'll have to install it first.

You'll need Cargo, Rust's package manager.
If you don't already have it,
go to the [Rust][rust] home page,
then download and install Rust for your platform,
which will install the Rust compiler and Cargo.

## Usage

### Installation

In a terminal or command prompt,
run the following command:

    $ cargo install feeds-to-bag

This will install the last version of <b>Feeds to Bag</b>
that was published to [crates.io][crate].

If you want to install an update, run:

    $ cargo install --force feeds-to-bag

[openssl]: https://www.openssl.org/
[rust]: https://www.rust-lang.org/
[crate]: https://crates.io/crates/feeds-to-bag

### Configuration

<b>Feeds to Bag</b> uses a file to store your configuration
(list of feeds to monitor, Wallabag access credentials).
You must specify a file name as a command-line argument
when you call the program;
there's no default file name.

First, you must create your configuration file:

    $ feeds-to-bag ~/feeds-to-bag.yaml init

> `~/feeds-to-bag.yaml` is just an example,
> you can use any file name you want!

Then, you must [create an application][create-app]
on the developer section of Wallabag instance.
Make sure you select at least the <b>Add</b> permission.
This will give you a _consumer key_,
which is necessary to use Wallabags's API.
Customer keys have [rate limits][rate-limits],
so I suggest you keep your consumer key private.

When you've obtained your consumer key,
save it in your configuration file:

    $ feeds-to-bag ~/feeds-to-bag.yaml set-consumer-key 1234-abcd1234abcd1234abcd1234

After that, you need to login.
Just run:

    $ feeds-to-bag ~/feeds-to-bag.yaml login

and follow the instructions.
This will save an access token in your configuration file.
The access token acts like your account's password,
so keep it safe!

Congratulations, <b>Feeds to Bag</b> is now ready to talk to Wallabag!

### Adding feeds

Once the above configuration steps are done,
you're ready to add feeds.
Use the `add` subcommand to add a feed:

    $ feeds-to-bag ~/feeds-to-bag.yaml add https://xkcd.com/atom.xml

This will download the feed
and mark all current entries as "processed"
without sending them to Wallabag.
If you would like all current entries to be sent to Wallabag,
pass the `--unread` flag:

    $ feeds-to-bag ~/feeds-to-bag.yaml add --unread https://xkcd.com/atom.xml

Repeat this for every feed you'd like <b>Feeds to Bag</b> to monitor.

### Sending new entries to Wallabag

Call `feeds-to-bag` without a subcommand
to have it download your feeds
and send new entries to Wallabag.

    $ feeds-to-bag ~/feeds-to-bag.yaml

Once an entry has been sent to Wallabag,
<b>Feeds to Bag</b> marks it as "processed"
and will not send it again.

### Assigning tags to feeds

You can assign tags to feeds.
When a new entry is pushed to Wallabag,
it will be assigned the tags that were set
on the feed the entry comes from.

To do this, pass the `--tags` option
to the `add` subcommand.
You can do this while adding a new feed
or for an existing feed
(then it will _replace_ the list of tags for that feed).
The `--tags` option is followed by a comma-separated list of tags.

    $ feeds-to-bag ~/feeds-to-bag.yaml add --tags comics,xkcd https://xkcd.com/atom.xml

### Scheduling

<b>Feeds to Bag</b> doesn't have any built-in scheduling mechanisms.
You should use an existing task scheduler
to run the `feeds-to-bag` program periodically.

If you are using Linux with systemd,
you can set up a systemd timer
for your systemd user instance.
See the example unit files in the `systemd-examples` directory.

[create-app]: https://getpocket.com/developer/apps/new
[rate-limits]: https://getpocket.com/developer/docs/rate-limits

### Removing feeds

Use the `remove` subcommand to remove a feed:

    $ feeds-to-bag ~/feeds-to-bag.yaml remove https://xkcd.com/atom.xml

## Compiling from source

To build the project, just run:

    $ cargo build

from the project's directory.
This will download and compile
all of the project's Rust dependencies automatically.

## Issues

If you find a bug,
first check if you're using the latest version,
and update if that's not the case.
If the bug still occurs,
please check if there's already a similar [issue][issues]
(check both open and closed issues!).
If there isn't, then [file a new issue][new-issue].
If the program outputs an error message,
please include it in your issue.
Also mention what operating system you're using and which version.

[issues]: https://github.com/joshuaCrewe/feeds-to-bag/issues
[new-issue]: https://github.com/joshuaCrewe/feeds-to-bag/issues/new

## Contributing

See [CONTRIBUTING][contributing].

[contributing]: CONTRIBUTING.md
