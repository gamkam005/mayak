from PIL import Image, ImageDraw
def icon(sz, path):
    S = 4*sz; im = Image.new('RGBA', (S, S), (0,0,0,0)); d = ImageDraw.Draw(im)
    d.rounded_rectangle([0,0,S-1,S-1], radius=S//5, fill=(11,16,32,255))
    cx = S/2; u = S/32
    d.polygon([(cx-9*u,9*u),(cx-2*u,11.5*u),(cx-2*u,13.5*u)], fill=(255,184,61,110))
    d.polygon([(cx+9*u,9*u),(cx+2*u,11.5*u),(cx+2*u,13.5*u)], fill=(255,184,61,110))
    d.polygon([(cx,5*u),(cx+2.5*u,8*u),(cx-2.5*u,8*u)], fill=(255,184,61,255))
    d.rectangle([cx-3*u,8*u,cx+3*u,11*u], fill=(255,184,61,255))
    d.polygon([(cx-3*u,11*u),(cx+3*u,11*u),(cx+5*u,26*u),(cx-5*u,26*u)], fill=(230,235,247,255))
    d.polygon([(cx-3.6*u,15*u),(cx+3.6*u,15*u),(cx+4*u,17.5*u),(cx-4*u,17.5*u)], fill=(255,93,115,255))
    d.polygon([(cx-4.4*u,21*u),(cx+4.4*u,21*u),(cx+4.8*u,23.5*u),(cx-4.8*u,23.5*u)], fill=(255,93,115,255))
    d.rounded_rectangle([cx-10*u,26*u,cx+10*u,27.5*u], radius=u, fill=(89,166,255,255))
    im.resize((sz, sz), Image.LANCZOS).save(path)
icon(144, 'res/mipmap-xxhdpi/ic_launcher.png'); icon(48, 'res/mipmap-mdpi/ic_launcher.png'); icon(512, '../docs/icon-512.png')
