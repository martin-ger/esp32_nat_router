#!/usr/bin/env python3

import os, htmlmin, sys


def shrinkHtml():
    cwd = os.getcwd()
    print(cwd)
    directory = os.fsencode('src/pages/')

    for f in os.listdir(directory):
        filename = os.fsdecode(f)
        if filename.endswith(".html"):
            file = open(os.path.join(directory, f))
            html = file.read().replace("\n", " ")
            file.close()
            minified = htmlmin.minify(html, remove_empty_space=True, remove_optional_attribute_quotes=False)
            print(minified)
            with open(os.path.join(directory, f), "w") as myfile:
                myfile.write(minified)
            continue
        else:
            continue


def main(argv):
    shrinkHtml()


if __name__ == "__main__":
    main(sys.argv[1:])