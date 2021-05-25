FROM ruby:3.0.1-buster

RUN apt-get update && apt-get install -y groff
RUN bundle config --global frozen 1
COPY Gemfile Gemfile.lock ./
RUN bundle install
ENTRYPOINT ["bash", "-O", "globstar", "-c", \
    "/usr/local/bundle/bin/ronn **/*.ronn"]
