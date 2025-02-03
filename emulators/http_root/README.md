# Customizing HTTP(S)

## Important Note

Any file with the name "README.md" will explicity return a 404, so feel free to add your own README.md files with content to describe what you have done within that directory.

## Default Document

Within `config.yml`, you will find a setting under "services.http" for a `default_doc`. The default setting for this is `index.html`, but you may change this as you please. By having this set, any sub-directory within this `http_root` folder will look for a default document to load. If there is no default document, a 404 will be returned to the client.

## Protected Files

To protect files with our basic authentication, place the following string as the first line in the document:

```html
<!-- PROTECTED -->
```

Any files containing this string as the first line will only be served after the user authenticates with our terrible credentials.
