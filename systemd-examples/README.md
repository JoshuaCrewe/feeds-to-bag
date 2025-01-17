# systemd example units

If you would like to use systemd as a scheduler for <b>Feeds to Bag</b>,
you can use the unit files in this directory as a basis.
You will most likely want to set this up for your user instance,
rather than for the system instance,
so copy `feeds-to-bag.service` and `feeds-to-bag.timer`
to `~/.config/systemd/user`.

In `feeds-to-bag.service`,
edit the `ExecStart` option in the `[Service]` section
to refer to your own configuration file.

In `feeds-to-bag.timer`,
you may configure the frequency
at which <b>Feeds to Bag</b> will run.
The provided timer will run 1 minute after login
and every hour after that.

Once you've configured the unit files to your liking,
enable the timer with the following command:

    $ systemctl --user enable feeds-to-bag.timer

When the timer is enabled,
it will be started automatically when you log in.

You can start the timer without having to log out and log back in
with the following command:

    $ systemctl --user start feeds-to-bag.timer

You can also run <b>Feeds to Bag</b> at any time
with the following command:

    $ systemctl --user start feeds-to-bag.service

systemd will capture <b>Feeds To Bag</b>'s output
and save it in its journal.
You can view the captured output
with this command:

    $ journalctl --user-unit feeds-to-bag.service
