/js-file-line/ {
    i = index($0, ">")
    str = substr($0, i+1)
    i = index(str, "<")
    str = substr(str, 1, i-1)
    if (length(str) >= 8)
       print str
}

