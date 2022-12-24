# Where to find the token needed for registration

1. After the application opens the browser page `https://<your-org-name>.cloudflareaccess.com/warp`,
   complete the authentication. Your page should then look like this:
   ![img1](https://user-images.githubusercontent.com/53291983/209418256-d2d3cdf5-ebd6-422c-b6cf-b01fdf9c50d2.png)

2. Now open your browser developer tools, inspect the DOM element. Open then `head` element,
   there should be a meta element containing a very long url attribute. Copy the token part,
   that is, the string after `?token=` that starts with `eyJhb` as shown in the following image:
   ![img2](https://user-images.githubusercontent.com/53291983/209418258-fc661e80-3dab-4dd6-b5c3-45f15abedcbe.png)

3. Paste the token into the stdin of the program and press enter.
