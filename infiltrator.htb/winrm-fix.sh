#!/usr/bin/env zsh

# Uninstall possible current installed versions
sudo gem uninstall evil-winrm -q
gem uninstall evil-winrm -q

# Install rbenv
sudo apt install rbenv

# Config rbenv on zshrc config file
echo 'export PATH="$HOME/.rbenv/bin:$PATH"' >> ~/.zshrc
echo 'eval "$(rbenv init -)"' >> ~/.zshrc
source ~/.zshrc

# Install ruby with readline support
export RUBY_CONFIGURE_OPTS=--with-readline-dir="/usr/include/readline"
rbenv install 2.7.1

# Create file '.ruby-version' to set right ruby version
rbenv local 2.7.1

# Install local gems
gem install bundler
bundle install

current_evwr="$(pwd)/evil-winrm.rb"

sudo bash -c "cat << 'EOF' > /usr/bin/evil-winrm
    #!/usr/bin/env sh
    "${current_evwr}" "\$@"
EOF"

sudo chmod +x /usr/bin/evil-winrm
