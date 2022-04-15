# Personal Website

- forked from [link](https://github.com/YoussefRaafatNasry/portfolYOU)


### Guide

#### Image - `![alt text](<path-to-file> "image name")`

#### Local Projects

1. Add `project-name.md` or `project-name.html` to `_projects/`.
1. Add [front matter](https://jekyllrb.com/docs/front-matter/) to the top of your new project file.

    ```yaml
    ---
    name: Awesome Project
    tools: [Tool1, Tool2]
    image: image url or path here.
    description: Write project description here.
    ---
    ```

1. Add project body in markdown or html. Check available 'elements' folder to enjoy extra customization.
1. Deploy

#### Remote Projects

Remote Projects are imported automatically from GitHub. The name, description and topics are fetched from the given repository name. Note that the repository must be public and on your own account. To add a Remote Project, add the following lines to your existing front matter in `pages/projects.html`:

```yaml
---
remote_projects:
  - repo-name-1
  - repo-name-2
---
```

#### Posts

1. Add `YYYY-MM-DD-post-name.md` to `_posts/`.
1. Add [front matter](https://jekyllrb.com/docs/front-matter/) to the top of your new post file.

    ```yaml
    ---
    title: Awesome Title
    tags: [TAG 1, TAG 2]
    style: fill / border (choose one only)
    color: primary / secondary / success / danger / warning / info / light / dark (choose one only)
    description: Write post description here, or it will be the first 25 words of the post's body.
    ---
    ```

1. If you left both the style and color empty, the post's style is set to default style.
1. Add project body in markdown or html. Check available 'elements' folder to enjoy extra customization.
1. Deploy

#### Pages

1. Add `page-name.html` or `page-name.md` to `pages/`, `new subfolder` or to `root directory` of your project.
1. Add [front matter](https://jekyllrb.com/docs/front-matter/) to the top of your new page.

    ```yaml
    ---
    layout: default
    title: Page Name
    permalink: /page_permalink/ (the output path for the page)
    weight: 2 (the order of the page in the navigation bar)
    ---
    ```

1. The new page will be added to the navigation bar automatically.
1. Deploy

#### External Content

If you want your project, post or even the page to refer to an external resource, _**google.com** for example_, just add the following attribute to your front matter:

```yaml
---
external_url: https://google.com/
---
```

> 💡 **Pro Tip**  
> You can change `external_new_tab` in `_config.yml` to make the external URLs open in a new tab.

#### Skills

Add the following lines to `_data/programming-skills.yml` or `_data/other-skills.yml`.

```yaml
- name: Awesome Skill
  percentage: 95
  color: secondary / success / danger / warning / info / light / dark (choose one only, default is primary)
```

#### Skills Categories

1. Add `category_name-skills.yml` to `_data/`.
1. Add skills to the file using the previously mentioned method.
1. Open `pages/about.md`.
1. Add the following lines to the skills section between `<div class="row">` and `</div>`:

```liquid
{% raw %}{% include about/skills.html title="Category_Name Skills" source=site.data.category_name-skills %}{% endraw %}
```

#### Timeline Events

Add the following lines to `_data/timeline.yml`:

```yaml
- title: Awesome Item
  from: 2016
  to: 2018
  description: Write item description here.
```

#### Social Networks

portfolYOU provides a good number of social networks, but if you want to add your own, go on.

1. Add the following lines to `_data/social-media.yml`:

    ```yaml
    network_name:
      url   : https://www.network_name.com/
      icon  : fab fa-icon      # From FontAwesome (https://fontawesome.com/icons)
      color : 1da1f2           # Hex color code for hover
    ```

1. Then add the following to `_config` under the `author` key:

    ```yaml
    author:
      network_name : your_username_here
    ```

1. The new network will be added to your footer automatically.